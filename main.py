import argparse
import asyncio
import os
import socket
import tempfile
from pathlib import Path

from crypto import Identity
from network import P2PNode
from cli import run_cli
from logo import print_logo


def _clear_terminal() -> None:
    """Clear the terminal before showing the startup banner."""
    if os.name == "nt":
        os.system("cls")
    else:
        os.system("clear")


def find_free_port(preferred: int = 12345, attempts: int = 10) -> int:
    """Try a range of preferred ports, then fall back to an OS-assigned port."""
    for port in range(preferred, preferred + attempts):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("", port))
                return s.getsockname()[1]
        except OSError:
            continue
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def main():
    parser = argparse.ArgumentParser(
        description="FYM?! — peer-to-peer terminal messenger"
    )
    parser.add_argument("--name", default="anon", help="local nickname / profile")
    parser.add_argument("--host", default="0.0.0.0", help="listen host")
    parser.add_argument("--port", type=int, default=0, help="listen port (0 = auto)")
    parser.add_argument(
        "--bootstrap",
        default="",
        help="comma-separated host:port list to bootstrap from",
    )
    parser.add_argument(
        "--data-dir",
        default=None,
        help="directory for identity and contacts (default: data/<name>)",
    )
    parser.add_argument(
        "--upnp",
        action="store_true",
        help="try to open a UPnP/NAT-PMP port mapping on the router",
    )
    parser.add_argument(
        "--relay",
        default=None,
        help="host:port of a public relay server for NAT-to-NAT connections",
    )
    parser.add_argument(
        "--dht-port",
        type=int,
        default=0,
        help="port for Kademlia DHT UDP (0 = auto, -1 = disabled)",
    )
    parser.add_argument(
        "--dht-bootstrap",
        default="",
        help="comma-separated host:port list of existing Kademlia DHT nodes",
    )
    parser.add_argument(
        "--ephemeral",
        action="store_true",
        help="run in ephemeral mode: identity and contacts are temporary and removed on exit",
    )
    args = parser.parse_args()

    asyncio.run(run(args))


async def run(args):
    if args.port == 0:
        args.port = find_free_port()

    if args.data_dir:
        data_dir = Path(args.data_dir)
    elif args.ephemeral:
        data_dir = Path(tempfile.mkdtemp(prefix="fym_ephemeral_"))
    else:
        data_dir = Path("data") / args.name
    data_dir.mkdir(parents=True, exist_ok=True)
    identity_path = data_dir / "identity.key"

    if args.ephemeral:
        identity = Identity()
        identity.save(str(identity_path))
    elif identity_path.exists():
        identity = Identity.load(str(identity_path))
    else:
        identity = Identity()
        identity.save(str(identity_path))

    bootstrap = [b for b in args.bootstrap.split(",") if b]
    dht_bootstrap = [b for b in args.dht_bootstrap.split(",") if b]
    dht_port = args.dht_port if args.dht_port >= 0 else None
    if dht_port == 0:
        dht_port = find_free_port(preferred=args.port + 1000)
    node = P2PNode(
        identity, args.host, args.port, data_dir, bootstrap,
        upnp=args.upnp, relay_address=args.relay,
        dht_port=dht_port, dht_bootstrap=dht_bootstrap,
        ephemeral=args.ephemeral,
    )

    _clear_terminal()
    print_logo()
    await node.start()
    print(f"Listening on {args.host}:{args.port}")
    print(f"Your fingerprint: {identity.fingerprint}")
    if node.public_endpoint:
        print(f"Public endpoint: {node.public_endpoint}")
    elif args.upnp and node.upnp_status:
        print(f"UPnP: {node.upnp_status}")

    try:
        await run_cli(node)
    finally:
        await node.stop()


if __name__ == "__main__":
    main()
