import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout

from network import P2PNode


HELP_TEXT = """
Commands:
  /connect host:port|id    — connect to a peer by address or peer_id
  /msg <id|nick|room> <text> — send a direct message or to a room (by name or id)
  /chat <id|nick|room|room_name> — enter clean chat mode with a peer or room
  /back                    — return from clean chat mode to normal mode
  /room create [name]      — create a group chat room
  /room add <room_id|name> <peer_id|nick> — add a peer to a room and notify them
  /room msg <room_id|name> <text> — send a message to a room
  /rooms                   — list rooms
  /add <id|short_id> <nick> [addr] — save a contact (addr is optional; DHT resolves it)
  /contacts                — list known contacts
  /peers                   — list connected peers
  /help                    — show this help
  /quit or /exit           — exit the application
"""


@dataclass
class ChatState:
    """State for the clean chat mode."""
    active: bool = False
    target: Optional[str] = None
    kind: Optional[str] = None
    name: Optional[str] = None
    pending: list = field(default_factory=list)


def _fmt_time(ts: float) -> str:
    if ts is None:
        return ""
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S")


def _display_name(node: P2PNode, peer_id: str) -> str:
    if not peer_id:
        return "?"
    nickname = node.get_nickname(peer_id)
    return nickname if nickname else peer_id[:16]


async def _send_chat_line(node: P2PNode, state: ChatState, text: str) -> None:
    try:
        if state.kind == "room":
            await node.send_room_message(state.target, text)
        else:
            await node.send_message(state.target, text)
    except Exception as exc:
        print(f"! {exc}")


async def process_inbox(node: P2PNode, state: ChatState) -> None:
    while True:
        if state.pending and not state.active:
            event = state.pending.pop(0)
        else:
            event = await node.inbox.get()
        t = event.get("type")
        if state.active:
            if t == "message":
                room_id = event.get("room")
                if state.kind == "room":
                    if room_id != state.target:
                        state.pending.append(event)
                        continue
                    print(f"\n<{_display_name(node, event['from'])}> {event['text']}")
                    continue
                else:  # peer chat
                    if room_id is not None or event["from"] != state.target:
                        state.pending.append(event)
                        continue
                    print(f"\n<{_display_name(node, event['from'])}> {event['text']}")
                    continue
            elif t == "connected":
                print(f"\n[+] connected {_display_name(node, event['peer_id'])}")
                continue
            elif t == "disconnected":
                print(f"\n[-] disconnected {_display_name(node, event['peer_id'])}")
                continue
            # all other system events are suppressed in chat mode
            continue
        if t == "message":
            room_id = event.get("room")
            prefix = ""
            if room_id:
                room = node.rooms.get(room_id)
                name = room.name if room else room_id[:8]
                prefix = f"[{name}] "
            print(f"\n[{_fmt_time(event.get('timestamp'))}] {prefix}<{_display_name(node, event['from'])}> {event['text']}")
        elif t == "room_invite":
            room_id = event.get("room_id", "")
            name = event.get("room_name", room_id[:8] if room_id else "")
            print(f"\n[+] you were added to room '{name}' ({room_id[:8]}) by {_display_name(node, event['from'])}")
        elif t == "connected":
            print(f"\n[+] connected {_display_name(node, event['peer_id'])} @ {event['address']}")
        elif t == "disconnected":
            print(f"\n[-] disconnected {_display_name(node, event['peer_id'])}")
        elif t == "delivery":
            print(f"\n[ok] delivered {event.get('id', 'unknown')[:8]}")
        elif t == "error":
            print(f"\n[!] {event['message']}")
        elif t == "info":
            print(f"\n[i] {event['message']}")


async def handle_command(node: P2PNode, line: str, state: ChatState) -> None:
    parts = line.strip().split(maxsplit=2)
    if not parts:
        return

    cmd = parts[0].lower()

    if cmd == "/help":
        print(HELP_TEXT)

    elif cmd == "/chat":
        if len(parts) < 2:
            print("Usage: /chat <peer_id|nickname|room_id|room_name>")
            return
        target = parts[1]
        resolved_room = node.resolve_room(target)
        if resolved_room in node.rooms:
            state.active = True
            state.kind = "room"
            state.target = resolved_room
            state.name = node.rooms[resolved_room].name
            state.pending = []
            print(f"[chat] entered room '{state.name}' (type /back to return)")
        else:
            resolved_peer = node.resolve_peer(target)
            state.active = True
            state.kind = "peer"
            state.target = resolved_peer
            state.name = target
            state.pending = []
            name = _display_name(node, resolved_peer)
            print(f"[chat] entered chat with {name} (type /back to return)")

    elif cmd == "/back":
        if state.active:
            state.active = False
            print("[chat] returned to normal mode")
        else:
            print("[-] not in chat mode")

    elif cmd == "/connect":
        if len(parts) < 2:
            print("Usage: /connect host:port|peer_id")
            return
        asyncio.create_task(node.connect(parts[1]))

    elif cmd == "/msg":
        if len(parts) < 3:
            print("Usage: /msg <peer_id|nickname|room_id|room_name> <text>")
            return
        target = parts[1]
        text = parts[2]

        async def _send():
            try:
                resolved_room = node.resolve_room(target)
                if resolved_room in node.rooms:
                    msg_id = await node.send_room_message(resolved_room, text)
                    room = node.rooms.get(resolved_room)
                    room_label = room.name if room else resolved_room[:8]
                    print(f"[you -> room {room_label}] {text}")
                else:
                    resolved_peer = node.resolve_peer(target)
                    msg_id = await node.send_message(resolved_peer, text)
                    print(f"[you -> {_display_name(node, resolved_peer)}] {text}")
                print(f"[id] {msg_id[:8]}")
            except Exception as exc:
                print(f"[!] send failed: {exc}")

        asyncio.create_task(_send())

    elif cmd == "/add":
        tokens = line.split()
        if len(tokens) < 3:
            print("Usage: /add <peer_id|short_id> <nickname> [address]")
            return
        peer_id = tokens[1]
        nickname = tokens[2]
        address = tokens[3] if len(tokens) > 3 else None
        stored = node.add_contact(peer_id, nickname, address)
        print(f"[+] added {nickname} {stored[:16]} {address or ''}")

    elif cmd == "/room":
        tokens = line.split(maxsplit=3)
        if len(tokens) < 2:
            print("Usage: /room create [name] | /room add <room_id|room_name> <peer_id|nickname> | /room msg <room_id|room_name> <text>")
            return
        sub = tokens[1].lower()
        if sub == "create":
            name = tokens[2] if len(tokens) > 2 else ""
            room_id = node.create_room(name)
            print(f"[+] room created {room_id[:8]} (full id: {room_id})")
        elif sub == "add":
            if len(tokens) < 4:
                print("Usage: /room add <room_id|room_name> <peer_id|nickname>")
                return
            room_id, peer_id = tokens[2], tokens[3]
            resolved_room = node.resolve_room(room_id)
            if resolved_room not in node.rooms:
                print("[!] room not found")
                return

            async def _invite_and_add():
                try:
                    await node.invite_to_room(resolved_room, peer_id)
                    node.room_add(resolved_room, peer_id)
                    resolved_peer = node.resolve_peer(peer_id)
                    print(f"[+] added {_display_name(node, resolved_peer)} to room {node.rooms[resolved_room].name}")
                except Exception as exc:
                    print(f"[!] {exc}")

            asyncio.create_task(_invite_and_add())
        elif sub == "msg":
            if len(tokens) < 4:
                print("Usage: /room msg <room_id|room_name> <text>")
                return
            room_id, text = tokens[2], tokens[3]
            resolved_room = node.resolve_room(room_id)

            async def _send_room(room_id: str, text: str):
                try:
                    msg_id = await node.send_room_message(room_id, text)
                    room = node.rooms.get(room_id)
                    print(f"[you -> room {room.name if room else room_id[:8]}] {text}")
                    print(f"[id] {msg_id[:8]}")
                except Exception as exc:
                    print(f"[!] room send failed: {exc}")

            asyncio.create_task(_send_room(resolved_room, text))
        else:
            print("Unknown /room subcommand")

    elif cmd == "/rooms":
        if not node.rooms:
            print("No rooms yet.")
        else:
            for room_id, room in node.rooms.items():
                print(f"  {room.name:12} {room_id[:8]} members={room.list_members()}")

    elif cmd == "/contacts":
        if not node.contacts.contacts:
            print("No contacts yet.")
        else:
            for pid, info in node.contacts.contacts.items():
                addr = info.get("address") or node.contacts.get_address(pid) or "?"
                print(f"  {info['nickname']:12} {pid[:16]} {addr}")

    elif cmd == "/peers":
        if not node.sessions:
            print("No active peer sessions.")
        else:
            for pid in node.sessions:
                print(f"  {_display_name(node, pid)}")

    elif cmd in ("/quit", "/exit"):
        raise SystemExit

    else:
        print("Unknown command. Use /help")


async def run_cli(node: P2PNode) -> None:
    session = PromptSession("> ")
    state = ChatState()
    print(HELP_TEXT)
    print(f"Your ID: {node.identity.id}")
    print(f"Your fingerprint: {node.identity.fingerprint}")

    with patch_stdout():
        inbox_task = asyncio.create_task(process_inbox(node, state))
        try:
            while True:
                try:
                    line = await session.prompt_async()
                except EOFError:
                    print("\n[i] use /quit or /exit to leave")
                    continue
                except KeyboardInterrupt:
                    print("\n[i] use /quit or /exit to leave")
                    continue
                line = line.strip()
                if not line:
                    continue
                try:
                    if state.active:
                        if line.startswith("/"):
                            cmd = line.split()[0].lower()
                            if cmd == "/back":
                                state.active = False
                                print("[chat] returned to normal mode")
                                node.inbox.put_nowait({"type": "noop"})
                            elif cmd in ("/quit", "/exit"):
                                break
                            elif cmd == "/help":
                                print("In chat mode: type text to send, /back to return, /quit to exit")
                            else:
                                print("Use /back to return")
                        else:
                            asyncio.create_task(_send_chat_line(node, state, line))
                    else:
                        await handle_command(node, line, state)
                except SystemExit:
                    break
        finally:
            inbox_task.cancel()
            try:
                await inbox_task
            except asyncio.CancelledError:
                pass
