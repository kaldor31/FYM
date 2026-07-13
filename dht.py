#!/usr/bin/env python3
"""Kademlia DHT wrapper for peer discovery.

Replaces/extends the manual bootstrap list. Each peer stores its own
TCP address under its peer_id key and can look up others by peer_id.
"""

import asyncio
from typing import Optional, List

from kademlia.network import Server
from kademlia.node import Node
from kademlia.utils import digest


class DHT:
    """Asyncio wrapper around kademlia's Server."""

    def __init__(self, node_id: str, port: int, host: str = "0.0.0.0",
                 bootstrap: List[str] = None):
        self.node_id = node_id
        self.port = port
        self.host = host
        self.bootstrap = self._parse_bootstrap(bootstrap or [])
        self.server = Server(node_id=digest(node_id.encode()))

    def _parse_bootstrap(self, addrs: List[str]) -> List[tuple]:
        out = []
        for a in addrs:
            if not a:
                continue
            host, _, port = a.rpartition(":")
            if host:
                try:
                    out.append((host, int(port)))
                except ValueError:
                    pass
        return out

    async def start(self) -> None:
        await self.server.listen(self.port, interface=self.host)
        if self.bootstrap:
            await self.server.bootstrap(self.bootstrap)

    async def stop(self) -> None:
        self.server.stop()

    async def set(self, key: str, value: str) -> None:
        """Store value locally and propagate to the DHT network."""
        # Always store locally so the node can answer queries immediately.
        dkey = digest(key)
        self.server.storage[dkey] = value
        # Only try to publish to the network if we know any neighbors.
        if self.server.protocol and self.server.protocol.router.find_neighbors(Node(dkey)):
            await self.server.set(key, value)

    async def get(self, key: str) -> Optional[str]:
        return await self.server.get(key)
