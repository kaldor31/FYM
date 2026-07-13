import ipaddress
import socket
from typing import Optional, Tuple


def is_public_ip(ip: str) -> bool:
    """Return True if the IP is globally routable (not private/CGNAT/loopback/etc)."""
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def get_local_ip() -> str:
    """Get the local IP used for default internet traffic."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(2)
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


def _wan_service(device):
    """Locate a WANIPConn/WANPPPConn service on a UPnP device."""
    candidates = ["WANIPConn1", "WANPPPConn1", "WANIPConn2", "WANIPConnection1"]
    for name in candidates:
        try:
            service = getattr(device, name)
            if "AddPortMapping" in [a.name for a in service.actions]:
                return service
        except Exception:
            continue
    return None


def upnp_map_port(
    internal_port: int,
    external_port: Optional[int] = None,
    description: str = "FYM Chat",
    lease_duration: int = 0,
) -> Tuple[Optional[str], Optional[int], bool, Optional[str]]:
    """Try to create a UPnP IGD port mapping and return (external_ip, external_port, ok, device_location)."""
    try:
        import upnpclient
    except ImportError:
        return None, None, False, None

    external_port = external_port or internal_port
    local_ip = get_local_ip()

    try:
        devices = upnpclient.discover(timeout=3)
    except Exception:
        return None, None, False, None

    for device in devices:
        service = _wan_service(device)
        if not service:
            continue
        try:
            external_ip = service.GetExternalIPAddress()["NewExternalIPAddress"]
            if not external_ip:
                continue
            if not is_public_ip(external_ip):
                return external_ip, external_port, False, device.location
            service.AddPortMapping(
                NewRemoteHost="",
                NewExternalPort=external_port,
                NewProtocol="TCP",
                NewInternalPort=internal_port,
                NewInternalClient=local_ip,
                NewEnabled="1",
                NewPortMappingDescription=description,
                NewLeaseDuration=lease_duration,
            )
            return external_ip, external_port, True, device.location
        except Exception:
            continue

    return None, None, False, None


def upnp_remove_port_mapping(external_port: int, device_location: Optional[str] = None) -> bool:
    """Try to remove a previously created UPnP port mapping on a specific device."""
    try:
        import upnpclient
    except ImportError:
        return False

    try:
        devices = upnpclient.discover(timeout=3)
    except Exception:
        return False

    for device in devices:
        if device_location and device.location != device_location:
            continue
        service = _wan_service(device)
        if not service:
            continue
        try:
            service.DeletePortMapping(
                NewRemoteHost="",
                NewExternalPort=external_port,
                NewProtocol="TCP",
            )
            return True
        except Exception:
            continue

    return False
