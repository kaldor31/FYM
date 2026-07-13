#!/usr/bin/env python3
"""Self-hosted message relay for NAT-to-NAT FYM chat.

Protocol (JSON line over TCP):
  {"type": "register", "id": "<peer_id>"}
  {"type": "relay", "to": "<peer_id>", "payload": "<base64>"}
  {"type": "ping"}

Server forwards:
  {"type": "relay", "from": "<sender_id>", "payload": "<base64>"}
  {"type": "pong"}
  {"type": "error", "message": "..."}

Offline messages are buffered up to MAX_QUEUE per peer.
"""

import argparse
import asyncio
import base64
import json
import logging
from collections import defaultdict, deque
from typing import Dict, Optional

MAX_QUEUE = 100

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)


class RelayClient:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer
        self.peer_id: Optional[str] = None

    def getname(self) -> str:
        return self.writer.get_extra_info("peername", ("?", 0))[0]

    async def send(self, payload: dict) -> None:
        line = json.dumps(payload).encode() + b"\n"
        self.writer.write(line)
        await self.writer.drain()


class RelayServer:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.clients: Dict[str, RelayClient] = {}
        self.offline_queue: Dict[str, deque] = defaultdict(deque)
        self.server: Optional[asyncio.Server] = None

    async def start(self) -> None:
        self.server = await asyncio.start_server(self._handle, self.host, self.port)
        log.info("Relay listening on %s:%d", self.host, self.port)

    async def stop(self) -> None:
        if self.server:
            self.server.close()
            await self.server.wait_closed()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        client = RelayClient(reader, writer)
        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                try:
                    msg = json.loads(line.decode())
                except Exception:
                    await client.send({"type": "error", "message": "invalid JSON"})
                    continue
                await self._process_message(client, msg)
        except asyncio.IncompleteReadError:
            pass
        except Exception as exc:
            log.warning("Client error %s: %s", client.getname(), exc)
        finally:
            if client.peer_id and self.clients.get(client.peer_id) is client:
                del self.clients[client.peer_id]
                log.info("Peer %s disconnected", client.peer_id[:16])
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def _process_message(self, client: RelayClient, msg: dict) -> None:
        t = msg.get("type")
        if t == "register":
            peer_id = msg.get("id")
            if not peer_id:
                await client.send({"type": "error", "message": "missing id"})
                return
            client.peer_id = peer_id
            self.clients[peer_id] = client
            log.info("Peer %s registered from %s", peer_id[:16], client.getname())
            # deliver buffered messages
            queue = self.offline_queue.pop(peer_id, None)
            if queue:
                while queue:
                    payload = queue.popleft()
                    await client.send(payload)
                    if client.writer.is_closing():
                        break
            await client.send({"type": "info", "message": "registered"})
        elif t == "relay":
            if not client.peer_id:
                await client.send({"type": "error", "message": "register first"})
                return
            target_id = msg.get("to")
            payload = msg.get("payload")
            if not target_id or not isinstance(payload, str):
                await client.send({"type": "error", "message": "bad relay payload"})
                return
            out = {"type": "relay", "from": client.peer_id, "payload": payload}
            target = self.clients.get(target_id)
            if target:
                try:
                    await target.send(out)
                except Exception:
                    self._buffer(target_id, out)
            else:
                self._buffer(target_id, out)
        elif t == "ping":
            await client.send({"type": "pong"})
        else:
            await client.send({"type": "error", "message": "unknown type"})

    def _buffer(self, peer_id: str, payload: dict) -> None:
        q = self.offline_queue[peer_id]
        q.append(payload)
        if len(q) > MAX_QUEUE:
            q.popleft()


def main():
    parser = argparse.ArgumentParser(description="FYM Chat Relay")
    parser.add_argument("--host", default="0.0.0.0", help="listen host")
    parser.add_argument("--port", type=int, default=20000, help="listen port")
    args = parser.parse_args()

    server = RelayServer(args.host, args.port)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(server.start())
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        loop.run_until_complete(server.stop())
        loop.close()


if __name__ == "__main__":
    main()
