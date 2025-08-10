import asyncio
import ipaddress
from typing import List, Tuple
from .utils import ping_ip, scan_ports

COMMON_PORTS = [22, 80, 443, 8080]

async def scan_ip(ip: str, scan_ports_flag: bool) -> Tuple[str, bool, float, List[int]]:
    """
    Scan complet d'une IP : ping + scan ports (optionnel).
    """
    ip_addr, is_active, ping_time = await ping_ip(ip)
    ports = []
    if is_active and scan_ports_flag:
        ports = await scan_ports(ip, COMMON_PORTS)
    return (ip_addr, is_active, ping_time, ports)

async def scan_range(ip_range: str, scan_ports_flag: bool) -> List[Tuple[str, bool, float, List[int]]]:
    """
    Scan une plage IP.
    """
    network = ipaddress.ip_network(ip_range, strict=False)
    tasks = [scan_ip(str(ip), scan_ports_flag) for ip in network.hosts()]
    return await asyncio.gather(*tasks)

async def scan_file(ip_file: str, scan_ports_flag: bool) -> List[Tuple[str, bool, float, List[int]]]:
    """
    Scan une liste d’IPs depuis un fichier.
    """
    with open(ip_file, 'r') as f:
        ips = [line.strip() for line in f if line.strip()]
    tasks = [scan_ip(ip, scan_ports_flag) for ip in ips]
    return await asyncio.gather(*tasks)

def save_results(results: List[Tuple[str, bool, float, List[int]]], filename='results.csv'):
    """
    Sauvegarde les résultats dans un fichier CSV.
    """
    import csv
    with open(filename, 'w', newline='') as csvfile:
        fieldnames = ['IP', 'Status', 'Ping (ms)', 'Open Ports']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for ip, active, ping, ports in results:
            writer.writerow({
                'IP': ip,
                'Status': 'Active' if active else 'Inactive',
                'Ping (ms)': round(ping) if active else '',
                'Open Ports': ','.join(str(p) for p in ports) if ports else ''
            })
