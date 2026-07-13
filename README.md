# FYM?!

A terminal peer-to-peer messenger with **Perfect Forward Secrecy** (PFS) and no central server.

## Overview

- **Decentralized**: every node is both a client and a server. There is no single point of failure or censorship.
- **PFS via ephemeral Diffie-Hellman (X25519)**: fresh one-time keys are generated for each connection. Even if the long-term identity key leaks, past sessions stay unreadable.
- **Ed25519 authentication**: the identity key signs the ephemeral key, preventing MITM attacks.
- **Encryption**: ChaCha20-Poly1305 with keys derived from the shared secret (HKDF-SHA256).
- **Double Ratchet**: during a long-lived session, keys rotate periodically through X25519 DH rounds — providing break-in recovery and future secrecy.
- **Kademlia DHT**: decentralized peer discovery by `peer_id` without a central bootstrap list.
- **Terminal**: command-line interface, no GUI.
- **Internet-ready**: listens on a TCP port, connects to other nodes by IP/host, DHT, relay, or UPnP.

## Architecture

```
run.py              main.py
  |                   |
  v                   v
cross-platform      cli.py  ->  network.py  ->  crypto.py + double_ratchet.py
launcher               |          |                 |
                PromptSession  P2PNode          Identity + DoubleRatchet
                               |                    |
                         Contacts + Session      DHT (Kademlia)
                               |                    |
                          relay.py               nat.py
                          relay_client.py        logo.py
```

- `crypto.py` — key generation, ephemeral DH, handshake, and symmetric encryption.
- `double_ratchet.py` — Double Ratchet (X25519 DH + KDF chain) for forward/future secrecy within a session.
- `dht.py` — Kademlia DHT (UDP) for peer discovery and address lookup.
- `network.py` — asyncio TCP server/client, handshake, peer exchange, message routing, rooms.
- `relay.py` / `relay_client.py` — self-hosted relay for NAT-to-NAT connections.
- `nat.py` — UPnP/NAT-PMP port mapping helpers.
- `cli.py` — terminal UI based on `prompt_toolkit`.
- `main.py` — entry point.
- `run.py` — cross-platform launcher that creates a virtual environment and installs dependencies.
- `logo.py` — ASCII art banner (placeholder ready for the final logo).

## Quick Start

The `run.py` launcher handles everything: it creates `.venv`, installs dependencies, and runs `main.py`.

```bash
python run.py
```

- Port is picked automatically: first `12345–12354`, then a random free port if those are busy.
- Default data directory: `data/anon`.
- The node prints its listening port and fingerprint.

## Running Two Nodes Locally

```bash
# Alice
python run.py --name alice

# Bob
python run.py --name bob --bootstrap 127.0.0.1:<alice_port>
```

Use the `Listening on ...:<port>` line from Alice's terminal for `--bootstrap`.

## Command-line Options

```bash
python run.py --port 12345 --name alice --data-dir data/alice
```

- `--port` — listening port (`0` for auto).
- `--name` — local profile / nickname, default `anon`. Used to build `data/<name>`.
- `--data-dir` — explicit data directory.
- `--bootstrap` — comma-separated `host:port` list of known TCP peers.
- `--dht-port` — Kademlia DHT UDP port (`0` for auto, `-1` to disable).
- `--dht-bootstrap` — comma-separated `host:port` list of Kademlia nodes.
- `--relay` — address of a public relay for NAT-to-NAT connections.
- `--upnp` — try automatic UPnP/NAT-PMP port mapping.
- `--ephemeral` — ephemeral mode: identity and contacts are not persisted, keys are wiped on exit.

If you prefer manual setup:

```bash
python3 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python main.py --name alice
```

Connect manually inside the CLI:

```
/connect 127.0.0.1:12345
```

## Commands

- `/connect host:port|peer_id` — connect to a peer by address or `peer_id` via DHT.
- `/msg <id|nickname|room_id> <text>` — send a direct message or a room message.
- `/room create [name]` — create a group chat room.
- `/room add <room_id> <peer_id|nickname>` — add a peer to a room.
- `/room msg <room_id> <text>` — send a message to a room.
- `/rooms` — list rooms.
- `/add <peer_id> <nickname> [address]` — save a contact (address is optional; DHT resolves it).
- `/contacts` — list known contacts.
- `/peers` — list connected peers.
- `/help` — show help.
- `/quit` — exit.

## Example Chat

```
> /connect 127.0.0.1:12345
[+] connected <...> @ 127.0.0.1:12345

> /msg <alice_fingerprint> hello
[you -> <...>] hello

# On the peer side:
[12:34:56] <bob_fingerprint> hello
```

## Decentralized Discovery (Kademlia DHT)

Each node publishes its TCP address in a Kademlia distributed hash table. You can connect to a peer by `peer_id` without typing the address.

```bash
# Alice — the first node in the network
python run.py --name alice --dht-port 13345

# Bob — joins Alice's DHT
python run.py --name bob --dht-port 13346 --dht-bootstrap 127.0.0.1:13345
```

Inside the CLI:

```
> /msg <alice_fingerprint> hello
# or
> /connect <alice_fingerprint>
```

## Ephemeral Mode

For maximum leave-no-trace behavior, run with `--ephemeral`:

```bash
python run.py --ephemeral --dht-port 13345
```

In this mode:
- A fresh identity is generated and not reused across runs.
- Contacts and routes are kept in memory only.
- On exit (`/quit` or Ctrl-C) the Double Ratchet keys are cleared, the inbox is drained, and the temporary data directory is removed.

## Group Chats

Rooms are created in memory locally. Messages are fanned out pairwise to each member through its own Double Ratchet session.

```
> /room create myteam
[+] room created aa02957b (full id: aa02957b...)

> /room add <room_id> <bob_fingerprint>
> /room add <room_id> <charlie_fingerprint>
# or /room add <room_id> <nickname> if the contact was saved with /add

> /room msg <room_id> hello everyone
```

When a group message is received, the room and its member list are automatically created/updated on the recipient side.

## Running Over the Internet

To let someone from outside connect, you need an open port. Three options:

1. **UPnP (automatic)** — if your router supports UPnP IGD:

```bash
python run.py --upnp --port 12345
```

On success, the terminal shows `Public endpoint: <your_public_ip>:<port>`. Share that address with the peer.

2. **Manual port forwarding** — open a TCP port in your router to the local IP of the machine.

3. **Self-hosted relay (VPS)** — when both peers are behind NAT/CGNAT. Run `relay.py` on a server with a public IP:

```bash
python relay.py --port 20000
```

Both clients connect to the relay:

```bash
# Alice
python run.py --name alice --relay <relay_ip>:20000

# Bob
python run.py --name bob --relay <relay_ip>:20000
```

Then Bob can message Alice by fingerprint:

```
> /msg <alice_fingerprint> hello
```

The relay only sees encrypted packets — it cannot decrypt messages.

## Project Structure

```
.
├── main.py              # Entry point
├── run.py               # Cross-platform launcher
├── cli.py               # Terminal UI
├── network.py           # P2P node, sessions, rooms, routing
├── crypto.py            # Key generation, handshake, session cipher
├── double_ratchet.py    # Double Ratchet implementation
├── dht.py               # Kademlia DHT node
├── relay.py             # Relay server
├── relay_client.py      # Relay client
├── nat.py               # UPnP helpers
├── logo.py              # ASCII art banner
├── requirements.txt     # Full pinned dependencies
└── .gitignore           # Git ignore rules
```
