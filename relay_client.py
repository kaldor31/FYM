import asyncio
import base64
import json
from typing import Any, Dict, Optional


class RelayStreamReader(asyncio.StreamReader):
    """StreamReader that can be fed raw bytes from a relay message."""

    def __init__(self):
        super().__init__()


class RelayStreamWriter:
    """StreamWriter-like wrapper that sends data as relay messages."""

    def __init__(self, relay_client: "RelayClient", target_id: str):
        self.relay_client = relay_client
        self.target_id = target_id
        self._buffer = bytearray()
        self._closed = False

    def write(self, data: bytes) -> None:
        self._buffer.extend(data)

    async def drain(self) -> None:
        if not self._buffer:
            return
        await self.relay_client.send_relay(self.target_id, bytes(self._buffer))
        self._buffer.clear()

    def close(self) -> None:
        self._closed = True

    async def wait_closed(self) -> None:
        pass

    def get_extra_info(self, name: str, default: Any = None) -> Any:
        if name == "peername":
            return ("relay", self.target_id)
        return default

    def is_closing(self) -> bool:
        return self._closed


class RelayClient:
    """Client for the relay.py message relay."""

    def __init__(self, node: Any = None):
        self.node = node
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.my_id: Optional[str] = None
        self._streams: Dict[str, RelayStreamReader] = {}
        self._running = False
        self._read_task: Optional[asyncio.Task] = None

    async def connect(self, address: str, peer_id: str) -> None:
        host, port = address.rsplit(":", 1)
        port = int(port)
        self.reader, self.writer = await asyncio.open_connection(host, port)
        self.my_id = peer_id
        self._running = True
        await self._send({"type": "register", "id": peer_id})
        self._read_task = asyncio.create_task(self._read_loop())

    async def stop(self) -> None:
        self._running = False
        if self.writer:
            self.writer.close()
            try:
                await self.writer.wait_closed()
            except Exception:
                pass
        if self._read_task:
            self._read_task.cancel()
            try:
                await self._read_task
            except asyncio.CancelledError:
                pass

    async def _send(self, payload: dict) -> None:
        line = json.dumps(payload).encode() + b"\n"
        self.writer.write(line)
        await self.writer.drain()

    async def send_relay(self, target_id: str, data: bytes) -> None:
        await self._send({
            "type": "relay",
            "to": target_id,
            "payload": base64.b64encode(data).decode(),
        })

    async def _read_loop(self) -> None:
        try:
            while self._running:
                line = await self.reader.readline()
                if not line:
                    break
                try:
                    msg = json.loads(line.decode())
                except Exception:
                    continue
                await self._process_message(msg)
        except asyncio.IncompleteReadError:
            pass
        finally:
            self._running = False

    async def _process_message(self, msg: dict) -> None:
        t = msg.get("type")
        if t == "relay":
            from_id = msg.get("from")
            payload_b64 = msg.get("payload")
            if not from_id or not isinstance(payload_b64, str):
                return
            try:
                data = base64.b64decode(payload_b64)
            except Exception:
                return
            await self._feed_stream(from_id, data)
        elif t == "pong":
            pass

    async def _feed_stream(self, from_id: str, data: bytes) -> None:
        stream = self._streams.get(from_id)
        if stream is None:
            if self.node is None:
                return
            # Ask node to create an incoming relay stream.
            stream = await self.node._accept_relay_stream(from_id)
            if stream is None:
                return
        stream.feed_data(data)

    def open_stream(self, target_id: str) -> tuple:
        """Open an outgoing relay stream to a target peer."""
        reader = RelayStreamReader()
        writer = RelayStreamWriter(self, target_id)
        self._streams[target_id] = reader
        return reader, writer

    def _on_stream_close(self, peer_id: str) -> None:
        self._streams.pop(peer_id, None)
