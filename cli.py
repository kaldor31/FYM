import asyncio
from datetime import datetime

from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout

from network import P2PNode


HELP_TEXT = """
Commands:
  /connect host:port|id    — connect to a peer by address or peer_id
  /msg <id|nick|room> <text> — send a direct message (or to a room if id is a room_id)
  /room create [name]      — create a group chat room
  /room add <room_id> <peer_id|nick> — add a peer to a room
  /room msg <room_id> <text> — send a message to a room
  /rooms                   — list rooms
  /add <id> <nick> [addr]  — save a contact (addr is optional; DHT resolves it)
  /contacts                — list known contacts
  /peers                   — list connected peers
  /help                    — show this help
  /quit                    — exit
"""


def _fmt_time(ts: float) -> str:
    if ts is None:
        return ""
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S")


async def process_inbox(node: P2PNode) -> None:
    while True:
        event = await node.inbox.get()
        t = event.get("type")
        if t == "message":
            room = event.get("room")
            prefix = f"[{room[:8]}] " if room else ""
            print(f"\n[{_fmt_time(event.get('timestamp'))}] {prefix}<{event['from'][:16]}> {event['text']}")
        elif t == "connected":
            print(f"\n[+] connected {event['peer_id'][:16]} @ {event['address']}")
        elif t == "disconnected":
            print(f"\n[-] disconnected {event['peer_id'][:16]}")
        elif t == "delivery":
            print(f"\n[ok] delivered {event.get('id', 'unknown')[:8]}")
        elif t == "error":
            print(f"\n[!] {event['message']}")
        elif t == "info":
            print(f"\n[i] {event['message']}")


async def handle_command(node: P2PNode, line: str) -> None:
    parts = line.strip().split(maxsplit=2)
    if not parts:
        return

    cmd = parts[0].lower()

    if cmd == "/help":
        print(HELP_TEXT)

    elif cmd == "/connect":
        if len(parts) < 2:
            print("Usage: /connect host:port|peer_id")
            return
        asyncio.create_task(node.connect(parts[1]))

    elif cmd == "/msg":
        if len(parts) < 3:
            print("Usage: /msg <peer_id|nickname|room_id> <text>")
            return
        target = parts[1]
        text = parts[2]

        async def _send():
            try:
                if target in node.rooms:
                    msg_id = await node.send_room_message(target, text)
                else:
                    msg_id = await node.send_message(target, text)
                print(f"[you -> {target[:16]}] {text}")
                print(f"[id] {msg_id[:8]}")
            except Exception as exc:
                print(f"[!] send failed: {exc}")

        asyncio.create_task(_send())

    elif cmd == "/add":
        tokens = line.split()
        if len(tokens) < 3:
            print("Usage: /add <peer_id> <nickname> [address]")
            return
        peer_id = tokens[1]
        nickname = tokens[2]
        address = tokens[3] if len(tokens) > 3 else None
        node.contacts.add(peer_id, nickname, address)
        print(f"[+] added {nickname} {peer_id[:16]} {address or ''}")

    elif cmd == "/room":
        tokens = line.split(maxsplit=3)
        if len(tokens) < 2:
            print("Usage: /room create [name] | /room add <room_id> <peer_id|nickname> | /room msg <room_id> <text>")
            return
        sub = tokens[1].lower()
        if sub == "create":
            name = tokens[2] if len(tokens) > 2 else ""
            room_id = node.create_room(name)
            print(f"[+] room created {room_id[:8]} (full id: {room_id})")
        elif sub == "add":
            if len(tokens) < 4:
                print("Usage: /room add <room_id> <peer_id|nickname>")
                return
            room_id, peer_id = tokens[2], tokens[3]
            try:
                node.room_add(room_id, peer_id)
                print(f"[+] added {peer_id[:16]} to room {room_id[:8]}")
            except Exception as exc:
                print(f"[!] {exc}")
        elif sub == "msg":
            if len(tokens) < 4:
                print("Usage: /room msg <room_id> <text>")
                return
            room_id, text = tokens[2], tokens[3]

            async def _send_room(room_id: str, text: str):
                try:
                    msg_id = await node.send_room_message(room_id, text)
                    print(f"[you -> room {room_id[:8]}] {text}")
                    print(f"[id] {msg_id[:8]}")
                except Exception as exc:
                    print(f"[!] room send failed: {exc}")

            asyncio.create_task(_send_room(room_id, text))
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
                print(f"  {pid[:16]}")

    elif cmd in ("/quit", "/exit"):
        raise SystemExit

    else:
        print("Unknown command. Use /help")


async def run_cli(node: P2PNode) -> None:
    session = PromptSession("> ")
    print(HELP_TEXT)
    print(f"Your ID: {node.identity.id}")
    print(f"Your fingerprint: {node.identity.fingerprint}")

    with patch_stdout():
        inbox_task = asyncio.create_task(process_inbox(node))
        try:
            while True:
                try:
                    line = await session.prompt_async()
                except (EOFError, KeyboardInterrupt):
                    break
                try:
                    await handle_command(node, line)
                except SystemExit:
                    break
        finally:
            inbox_task.cancel()
            try:
                await inbox_task
            except asyncio.CancelledError:
                pass
