import asyncio
import platform
import re
from typing import Tuple, List

async def ping_ip(ip: str) -> Tuple[str, bool, float]:
    """
    Ping une IP de manière asynchrone.

    Retourne (ip, is_active, ping_ms)
    """
    system = platform.system()
    if system == "Windows":
        count_flag = "-n"
        timeout_flag = "-w"
        timeout = "1000"  # en ms
    else:
        count_flag = "-c"
        timeout_flag = "-W"
        timeout = "1"  # en secondes

    proc = await asyncio.create_subprocess_exec(
        "ping", count_flag, "1", timeout_flag, timeout, ip,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )

    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=3)
    except asyncio.TimeoutError:
        return (ip, False, 0)

    output = stdout.decode()

    if re.search(r'time[=<]\d+\.?\d* ?ms', output, re.IGNORECASE):
        m = re.search(r'time[=<](\d+\.?\d*) ?ms', output, re.IGNORECASE)
        ping_time = float(m.group(1)) if m else 0.0
        return (ip, True, ping_time)
    else:
        return (ip, False, 0)

async def scan_ports(ip: str, ports: List[int]) -> List[int]:
    """
    Scan TCP simple des ports spécifiés.

    Retourne la liste des ports ouverts.
    """
    open_ports = []

    async def check_port(port):
        try:
            conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=1)
            writer.close()
            await writer.wait_closed()
            open_ports.append(port)
        except:
            pass

    tasks = [check_port(port) for port in ports]
    await asyncio.gather(*tasks)
    return open_ports
