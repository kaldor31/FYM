import asyncio
import base64
import json
import shutil
import struct
import time
import uuid
from pathlib import Path
from typing import Dict, Optional, Tuple

from crypto import Identity, EphemeralKey, encode_handshake, decode_handshake
from double_ratchet import DoubleRatchet
from nat import upnp_map_port, upnp_remove_port_mapping, get_local_ip
from relay_client import RelayClient
from dht import DHT


class Session:
    """Encrypted session with a single peer using Double Ratchet."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                 remote_id: str, cipher: DoubleRatchet, address: str, is_initiator: bool):
        self.reader = reader
        self.writer = writer
        self.remote_id = remote_id
        self.cipher = cipher
        self.address = address
        self.is_initiator = is_initiator

    async def send(self, payload: dict) -> None:
        data = json.dumps(payload).encode()
        packet = self.cipher.encrypt(data)
        msg = struct.pack(">I", len(packet)) + packet
        self.writer.write(msg)
        await self.writer.drain()

    def close(self) -> None:
        if self.cipher:
            self.cipher.clear()
            self.cipher = None
        try:
            if self.writer and not self.writer.is_closing():
                self.writer.close()
        except Exception:
            pass


class Contacts:
    """Tiny local address book / routing cache."""

    def __init__(self, data_dir: Path, memory_only: bool = False):
        self.data_dir = data_dir
        self.memory_only = memory_only
        self.contacts_path = data_dir / "contacts.json"
        self.routes_path = data_dir / "routes.json"
        self.contacts = self._load_json(self.contacts_path, {})
        self.routes = self._load_json(self.routes_path, {})

    def _load_json(self, path: Path, default: dict) -> dict:
        if self.memory_only or not path.exists():
            return default
        try:
            with open(path, "r") as f:
                return json.load(f)
        except Exception:
            return default

    def _save_json(self, path: Path, data: dict) -> None:
        if self.memory_only:
            return
        with open(path, "w") as f:
            json.dump(data, f, indent=2)

    def add(self, peer_id: str, nickname: str, address: Optional[str] = None) -> None:
        self.contacts[peer_id] = {"nickname": nickname, "address": address}
        if address:
            self.routes[peer_id] = address
        self._save_all()

    def get_address(self, peer_id: str) -> Optional[str]:
        return self.routes.get(peer_id) or self.contacts.get(peer_id, {}).get("address")

    def add_route(self, peer_id: str, address: str) -> None:
        self.routes[peer_id] = address
        self._save_json(self.routes_path, self.routes)

    def _save_all(self) -> None:
        self._save_json(self.contacts_path, self.contacts)
        self._save_json(self.routes_path, self.routes)


async def _write_handshake(writer: asyncio.StreamWriter, handshake: bytes) -> None:
    packet = struct.pack(">I", len(handshake)) + handshake
    writer.write(packet)
    await writer.drain()


async def _read_handshake(reader: asyncio.StreamReader) -> bytes:
    length_data = await reader.readexactly(4)
    length = struct.unpack(">I", length_data)[0]
    if length != 136:
        raise ValueError("unexpected handshake size")
    return await reader.readexactly(length)


async def handshake_initiate(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                             identity: Identity, ephemeral: EphemeralKey) -> tuple:
    """Perform handshake as TCP client."""
    out = encode_handshake(ephemeral, identity)
    await _write_handshake(writer, out)

    incoming = await _read_handshake(reader)
    remote_eph, remote_ts, remote_pub, remote_sig = decode_handshake(incoming)

    if not identity.verify_signature(remote_eph + remote_ts + remote_pub, remote_sig, remote_pub):
        raise ValueError("responder signature invalid")

    shared = ephemeral.shared_secret(remote_eph)
    remote_id = base64.urlsafe_b64encode(remote_pub).decode().rstrip("=")
    cipher = DoubleRatchet(
        shared, is_initiator=True,
        own_private_key_bytes=ephemeral.private_bytes,
        remote_public_key_bytes=remote_eph,
    )
    return remote_id, cipher


async def handshake_respond(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                            identity: Identity, ephemeral: EphemeralKey) -> tuple:
    """Perform handshake as TCP server."""
    incoming = await _read_handshake(reader)
    remote_eph, remote_ts, remote_pub, remote_sig = decode_handshake(incoming)

    if not identity.verify_signature(remote_eph + remote_ts + remote_pub, remote_sig, remote_pub):
        raise ValueError("initiator signature invalid")

    out = encode_handshake(ephemeral, identity)
    await _write_handshake(writer, out)

    shared = ephemeral.shared_secret(remote_eph)
    remote_id = base64.urlsafe_b64encode(remote_pub).decode().rstrip("=")
    cipher = DoubleRatchet(
        shared, is_initiator=False,
        own_private_key_bytes=ephemeral.private_bytes,
        remote_public_key_bytes=remote_eph,
    )
    return remote_id, cipher


class ChatRoom:
    """In-memory group chat room."""

    def __init__(self, room_id: str, name: str = ""):
        self.room_id = room_id
        self.name = name or room_id[:8]
        self.members = set()

    def add(self, peer_id: str) -> None:
        self.members.add(peer_id)

    def remove(self, peer_id: str) -> None:
        self.members.discard(peer_id)

    def list_members(self):
        return list(self.members)


class P2PNode:
    """FYM?! peer-to-peer node with ephemeral-key PFS per connection."""

    def __init__(self, identity: Identity, host: str, port: int, data_dir: Path,
                 bootstrap_peers: list = None, upnp: bool = False, relay_address: Optional[str] = None,
                 dht_port: Optional[int] = None, dht_bootstrap: list = None,
                 ephemeral: bool = False):
        self.identity = identity
        self.host = host
        self.port = port
        self.data_dir = data_dir
        self.ephemeral = ephemeral
        self.bootstrap_peers = bootstrap_peers or []
        self.upnp = upnp
        self.relay_address = relay_address
        self.relay_client: Optional[RelayClient] = None
        self.dht: Optional[DHT] = None
        self.dht_port = dht_port
        self.dht_bootstrap = dht_bootstrap or []
        self.sessions: Dict[str, Session] = {}
        self.rooms: Dict[str, ChatRoom] = {}
        self.contacts = Contacts(data_dir, memory_only=ephemeral)
        self.inbox: asyncio.Queue = asyncio.Queue()
        self.server: Optional[asyncio.Server] = None
        self._running = False
        self._pending_connections = set()
        self._pending_relay = set()
        self._receive_tasks = set()
        self._upnp_mapping: Optional[Tuple[str, int, str]] = None
        self.public_endpoint: Optional[str] = None
        self.upnp_status: Optional[str] = None

    async def start(self) -> None:
        self._running = True
        self.server = await asyncio.start_server(self._accept, self.host, self.port)
        if self.upnp:
            await self._try_upnp()
        if self.relay_address:
            self.relay_client = RelayClient(node=self)
            try:
                await self.relay_client.connect(self.relay_address, self.identity.id)
                await self.inbox.put({"type": "info", "message": f"Connected to relay {self.relay_address}"})
            except Exception as exc:
                await self.inbox.put({"type": "info", "message": f"Relay connection failed: {exc}"})
                self.relay_client = None
        if self.dht_port is not None:
            self.dht = DHT(
                self.identity.id, self.dht_port, host=self.host,
                bootstrap=self.dht_bootstrap,
            )
            try:
                await self.dht.start()
                await self.dht.set(self.identity.id, self._dht_address())
                await self.inbox.put({"type": "info", "message": f"DHT listening on {self.host}:{self.dht_port}"})
            except Exception as exc:
                await self.inbox.put({"type": "info", "message": f"DHT start failed: {exc}"})
                self.dht = None
        for b in self.bootstrap_peers:
            asyncio.create_task(self.connect(b))

    async def _try_upnp(self) -> None:
        try:
            external_ip, external_port, ok, device_location = await asyncio.to_thread(
                upnp_map_port, self.port, self.port, "FYM Chat"
            )
            if ok and external_ip and external_port:
                self._upnp_mapping = (external_ip, external_port, device_location)
                self.public_endpoint = f"{external_ip}:{external_port}"
                self.upnp_status = f"mapping OK: {external_ip}:{external_port} -> {get_local_ip()}:{self.port}"
                await self.inbox.put({"type": "info", "message": self.upnp_status})
            elif external_ip and external_port:
                # Router reported an IP, but it is not globally routable (CGNAT / double NAT).
                self.upnp_status = f"private external IP {external_ip}:{external_port} (likely CGNAT/double NAT); use a public relay or manual port forwarding"
                await self.inbox.put({"type": "info", "message": f"UPnP reports {self.upnp_status}"})
            else:
                self.upnp_status = "router may not support UPnP or it is disabled; use manual port forwarding"
                await self.inbox.put({"type": "info", "message": f"UPnP mapping failed: {self.upnp_status}"})
        except Exception as exc:
            self.upnp_status = f"error: {exc}"
            await self.inbox.put({"type": "info", "message": f"UPnP {self.upnp_status}"})

    async def stop(self) -> None:
        self._running = False
        # Cancel all receive tasks so the transport closes cleanly.
        for task in list(self._receive_tasks):
            task.cancel()
        if self._receive_tasks:
            await asyncio.gather(*self._receive_tasks, return_exceptions=True)
        for session in list(self.sessions.values()):
            session.close()
        self.sessions.clear()
        if self.server:
            self.server.close()
            try:
                await asyncio.wait_for(self.server.wait_closed(), timeout=2.0)
            except asyncio.TimeoutError:
                pass
        if self._upnp_mapping:
            _, external_port, device_location = self._upnp_mapping
            await asyncio.to_thread(upnp_remove_port_mapping, external_port, device_location)
            self._upnp_mapping = None
        if self.relay_client:
            await self.relay_client.stop()
            self.relay_client = None
        if self.dht:
            await self.dht.stop()
            self.dht = None

        # Wipe key material and in-memory state.
        if self.identity:
            self.identity.clear()
        self.rooms.clear()
        self.contacts.contacts.clear()
        self.contacts.routes.clear()
        while not self.inbox.empty():
            try:
                self.inbox.get_nowait()
            except asyncio.QueueEmpty:
                break

        # If ephemeral mode, remove the temporary data directory.
        if self.ephemeral and self.data_dir and self.data_dir.exists():
            try:
                shutil.rmtree(self.data_dir)
            except Exception:
                pass

    async def _accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer_addr = writer.get_extra_info("peername")
        address = f"{peer_addr[0]}:{peer_addr[1]}"
        ephemeral = EphemeralKey()
        try:
            remote_id, cipher = await asyncio.wait_for(
                handshake_respond(reader, writer, self.identity, ephemeral), timeout=10.0
            )
        except Exception as exc:
            writer.close()
            await writer.wait_closed()
            await self.inbox.put({"type": "error", "message": f"handshake from {address}: {exc}"})
            return

        session = Session(reader, writer, remote_id, cipher, address, is_initiator=False)
        self.sessions[remote_id] = session
        await self.inbox.put({"type": "connected", "peer_id": remote_id, "address": address})
        await self._post_handshake(session)
        task = asyncio.create_task(self._receive_loop(session))
        self._receive_tasks.add(task)
        task.add_done_callback(self._receive_tasks.discard)

    def _dht_address(self) -> str:
        """Address to advertise in the DHT (public if UPnP works, else local)."""
        if self.public_endpoint:
            return self.public_endpoint
        host = self.host if self.host != "0.0.0.0" else get_local_ip()
        return f"{host}:{self.port}"

    async def connect(self, address: str) -> Optional[str]:
        """Open an outgoing encrypted connection to address (host:port or peer_id)."""
        if address in self._pending_connections:
            return None
        self._pending_connections.add(address)
        try:
            if ":" not in address:
                # peer_id lookup via DHT / contacts
                target = self.resolve_peer(address)
                if await self._connect_by_id(target):
                    return target
                return None

            host, port = address.rsplit(":", 1)
            port = int(port)
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=5.0
            )
            ephemeral = EphemeralKey()
            remote_id, cipher = await asyncio.wait_for(
                handshake_initiate(reader, writer, self.identity, ephemeral), timeout=10.0
            )

            session = Session(reader, writer, remote_id, cipher, address, is_initiator=True)
            # If an inbound session already exists, prefer the first one.
            if remote_id in self.sessions:
                session.close()
            else:
                self.sessions[remote_id] = session
                await self.inbox.put({"type": "connected", "peer_id": remote_id, "address": address})
                await self._post_handshake(session)
                task = asyncio.create_task(self._receive_loop(session))
                self._receive_tasks.add(task)
                task.add_done_callback(self._receive_tasks.discard)
            return remote_id
        except Exception as exc:
            await self.inbox.put({"type": "error", "message": f"connect to {address}: {exc}"})
            return None
        finally:
            self._pending_connections.discard(address)

    async def _connect_by_id(self, target_id: str) -> bool:
        """Resolve a peer_id to an address and connect."""
        if target_id in self.sessions:
            return True
        addr = self.contacts.get_address(target_id)
        if not addr and self.dht:
            try:
                addr = await asyncio.wait_for(self.dht.get(target_id), timeout=5.0)
            except Exception:
                addr = None
        if addr:
            await self.connect(addr)
        return target_id in self.sessions

    async def _post_handshake(self, session: Session) -> None:
        """Send peer list to help decentralized discovery."""
        peers = []
        for pid, sess in self.sessions.items():
            if sess.is_initiator and sess.address:
                peers.append({"id": pid, "address": sess.address})
        if peers:
            try:
                await session.send({"type": "peer_list", "peers": peers})
            except Exception:
                pass

    async def _receive_loop(self, session: Session) -> None:
        try:
            while self._running:
                length_data = await session.reader.readexactly(4)
                length = struct.unpack(">I", length_data)[0]
                packet = await session.reader.readexactly(length)
                plaintext = session.cipher.decrypt(packet)
                payload = json.loads(plaintext.decode())
                await self._handle_payload(session, payload)
        except asyncio.IncompleteReadError:
            pass
        except Exception as exc:
            await self.inbox.put({"type": "error", "message": f"peer {session.remote_id[:16]}: {exc}"})
        finally:
            session.close()
            self.sessions.pop(session.remote_id, None)
            await self.inbox.put({"type": "disconnected", "peer_id": session.remote_id})

    async def _handle_payload(self, session: Session, payload: dict) -> None:
        t = payload.get("type")
        if t == "message":
            room_id = payload.get("room")
            if room_id:
                # Auto-join the room if we see a group message for it.
                if room_id not in self.rooms:
                    self.rooms[room_id] = ChatRoom(room_id, name=room_id[:8])
                room = self.rooms[room_id]
                room.add(session.remote_id)
                room.add(self.identity.id)
                for member in payload.get("members", []):
                    room.add(member)

            await self.inbox.put({
                "type": "message",
                "from": session.remote_id,
                "text": payload.get("text", ""),
                "id": payload.get("id"),
                "timestamp": payload.get("timestamp"),
                "room": room_id,
            })
            await session.send({"type": "delivery", "id": payload.get("id")})
        elif t == "delivery":
            await self.inbox.put({"type": "delivery", "id": payload.get("id")})
        elif t == "peer_list":
            for peer in payload.get("peers", []):
                pid = peer.get("id")
                addr = peer.get("address")
                if pid and addr:
                    self.contacts.add_route(pid, addr)

    async def _ensure_session(self, target: str) -> None:
        """Try to establish a session with a peer by any available means."""
        if target in self.sessions:
            return
        # 1) try DHT discovery
        if self.dht:
            try:
                addr = await asyncio.wait_for(self.dht.get(target), timeout=5.0)
            except Exception:
                addr = None
            if addr:
                await self.connect(addr)
        # 2) fallback to relay if available
        if target not in self.sessions and self.relay_client and self.relay_client._running:
            await self._relay_connect(target)
        # 3) fallback to known contacts
        if target not in self.sessions:
            addr = self.contacts.get_address(target)
            if addr:
                await self.connect(addr)

    async def send_message(self, peer_id: str, text: str, msg_id: Optional[str] = None,
                           room: Optional[str] = None, members: Optional[list] = None) -> str:
        target = self.resolve_peer(peer_id)
        await self._ensure_session(target)
        if target not in self.sessions:
            raise ValueError(f"peer {target[:16]} is unreachable")
        session = self.sessions[target]
        msg = {
            "type": "message",
            "id": msg_id or uuid.uuid4().hex,
            "text": text,
            "timestamp": time.time(),
        }
        if room:
            msg["room"] = room
        if members:
            msg["members"] = members
        await session.send(msg)
        return msg["id"]

    def create_room(self, name: str = "") -> str:
        """Create a new in-memory group chat room."""
        room_id = uuid.uuid4().hex
        self.rooms[room_id] = ChatRoom(room_id, name=name)
        return room_id

    def room_add(self, room_id: str, peer_id: str) -> None:
        """Add a peer to a local room. Accepts full id, nickname or prefix."""
        if room_id not in self.rooms:
            raise ValueError("room not found")
        resolved = self.resolve_peer(peer_id)
        self.rooms[room_id].add(resolved)

    def room_members(self, room_id: str) -> list:
        if room_id not in self.rooms:
            raise ValueError("room not found")
        return self.rooms[room_id].list_members()

    def list_rooms(self) -> Dict[str, ChatRoom]:
        return self.rooms

    async def send_room_message(self, room_id: str, text: str) -> str:
        """Send a message to all members of a room (pairwise fan-out)."""
        if room_id not in self.rooms:
            raise ValueError("room not found")
        room = self.rooms[room_id]
        if not room.members:
            raise ValueError("room has no members")
        members = list(room.members)
        msg_id = uuid.uuid4().hex
        failures = []
        for peer_id in members:
            if peer_id == self.identity.id:
                continue
            try:
                await self.send_message(peer_id, text, msg_id=msg_id, room=room_id, members=members)
            except Exception as exc:
                failures.append(f"{peer_id[:16]}: {exc}")
        if failures:
            raise ValueError("failed to reach some members: " + ", ".join(failures))
        return msg_id

    async def _relay_connect(self, target_id: str) -> Optional[str]:
        if target_id in self._pending_relay:
            return None
        self._pending_relay.add(target_id)
        try:
            reader, writer = self.relay_client.open_stream(target_id)
            ephemeral = EphemeralKey()
            remote_id, cipher = await asyncio.wait_for(
                handshake_initiate(reader, writer, self.identity, ephemeral), timeout=10.0
            )
            session = Session(reader, writer, remote_id, cipher, f"relay:{target_id}", is_initiator=True)
            if remote_id in self.sessions:
                session.close()
            else:
                self.sessions[remote_id] = session
                await self.inbox.put({"type": "connected", "peer_id": remote_id, "address": f"relay:{target_id}"})
                await self._post_handshake(session)
                task = asyncio.create_task(self._receive_loop(session))
                self._receive_tasks.add(task)
                task.add_done_callback(self._receive_tasks.discard)
            return remote_id
        except Exception as exc:
            await self.inbox.put({"type": "error", "message": f"relay connect to {target_id[:16]}: {exc}"})
            return None
        finally:
            self._pending_relay.discard(target_id)

    async def _accept_relay_stream(self, from_id: str):
        """Create an incoming relay stream and run the handshake responder."""
        reader, writer = self.relay_client.open_stream(from_id)
        ephemeral = EphemeralKey()
        asyncio.create_task(self._relay_handshake_respond(reader, writer, ephemeral, from_id))
        return reader

    async def _relay_handshake_respond(self, reader, writer, ephemeral, from_id):
        try:
            remote_id, cipher = await asyncio.wait_for(
                handshake_respond(reader, writer, self.identity, ephemeral), timeout=10.0
            )
        except Exception as exc:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            await self.inbox.put({"type": "error", "message": f"relay handshake from {from_id[:16]}: {exc}"})
            return
        session = Session(reader, writer, remote_id, cipher, f"relay:{from_id}", is_initiator=False)
        self.sessions[remote_id] = session
        await self.inbox.put({"type": "connected", "peer_id": remote_id, "address": f"relay:{from_id}"})
        await self._post_handshake(session)
        task = asyncio.create_task(self._receive_loop(session))
        self._receive_tasks.add(task)
        task.add_done_callback(self._receive_tasks.discard)

    def resolve_peer(self, key: str) -> str:
        """Resolve a nickname, full id or prefix to a peer id."""
        if key in self.sessions:
            return key
        if key in self.contacts.contacts:
            return key
        # nickname
        for pid, info in self.contacts.contacts.items():
            if info.get("nickname") == key:
                return pid
        # prefix
        for pid in list(self.sessions.keys()) + list(self.contacts.contacts.keys()):
            if pid.startswith(key):
                return pid
        return key
