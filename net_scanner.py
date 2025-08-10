import argparse
import asyncio
import ipaddress
import csv
from typing import List, Tuple

# Ports courants à scanner pour la fonction avancée
COMMON_PORTS = [22, 80, 443, 8080]

async def ping_ip(ip: str) -> Tuple[str, bool, float]:
    """
    Ping une IP de manière asynchrone.

    Retourne (ip, is_active, ping_ms)
    """
    # Commande ping adaptée selon OS
    # Windows utilise '-n 1', Linux/Mac '-c 1'
    count_flag = '-n' if asyncio.get_event_loop()._selector.__class__.__module__.startswith('selectors') else '-c'
    proc = await asyncio.create_subprocess_exec(
        'ping', count_flag, '1', '-W', '1', ip,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=3)
    except asyncio.TimeoutError:
        return (ip, False, 0)

    output = stdout.decode()

    if 'time=' in output.lower():
        # Extrait le temps de ping
        import re
        m = re.search(r'time[=<]([\d\.]+) ?ms', output)
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

async def scan_ip(ip: str, scan_ports_flag: bool) -> Tuple[str, bool, float, List[int]]:
    """
    Scan complet d'une IP : ping + ports (optionnel)
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

def main():
    parser = argparse.ArgumentParser(description="Net Scanner: scan IP ranges or list, detect active IPs and open ports.")
    subparsers = parser.add_subparsers(dest='command')

    scan_parser = subparsers.add_parser('scan', help='Lancer un scan')
    group = scan_parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--range', type=str, help='Plage d’adresses IP (ex: 192.168.1.0/24)')
    group.add_argument('--file', type=str, help='Fichier texte contenant la liste d’IPs')

    scan_parser.add_argument('--ports', action='store_true', help='Scanner les ports ouverts (option avancée)')

    args = parser.parse_args()

    if args.command == 'scan':
        if args.range:
            results = asyncio.run(scan_range(args.range, args.ports))
        else:
            results = asyncio.run(scan_file(args.file, args.ports))

        for ip, active, ping, ports in results:
            status = 'Active' if active else 'Inactive'
            ping_display = f"(Ping: {round(ping)}ms)" if active else ""
            ports_display = f"Ports ouverts: {','.join(str(p) for p in ports)}" if ports else ""
            print(f"{ip} {status} {ping_display} {ports_display}")

        save_results(results)
        print("Résultats sauvegardés dans results.csv")

    else:
        parser.print_help()

if __name__ == '__main__':
    main()
