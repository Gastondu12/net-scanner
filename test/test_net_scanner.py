import unittest
import asyncio
from unittest.mock import patch, AsyncMock
from src.net_scanner.scanner import ping_ip, scan_ip, scan_ports, scan_ips_from_range, scan_ips_from_file

class TestScanner(unittest.IsolatedAsyncioTestCase):
    async def test_ping_ip_active(self):
        with patch('asyncio.create_subprocess_exec') as mock_subproc:
            process_mock = AsyncMock()
            process_mock.communicate.return_value = (b'64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=5 ms', b'')
            process_mock.returncode = 0
            mock_subproc.return_value = process_mock
            result = await ping_ip('192.168.1.1')
            self.assertIsInstance(result, float)
            self.assertTrue(result >= 0)

    async def test_ping_ip_inactive(self):
        with patch('asyncio.create_subprocess_exec') as mock_subproc:
            process_mock = AsyncMock()
            process_mock.communicate.return_value = (b'', b'')
            process_mock.returncode = 1
            mock_subproc.return_value = process_mock
            result = await ping_ip('10.255.255.1')
            self.assertIsNone(result)

    async def test_scan_ip_active_no_ports(self):
        with patch('src.net_scanner.scanner.ping_ip', return_value=0.5):
            result = await scan_ip('192.168.1.1', [])
            self.assertEqual(result['ip'], '192.168.1.1')
            self.assertEqual(result['status'], 'Active')
            self.assertEqual(result['ping'], 0)
            self.assertEqual(result['open_ports'], [])

    async def test_scan_ip_inactive(self):
        with patch('src.net_scanner.scanner.ping_ip', return_value=None):
            result = await scan_ip('10.255.255.1', [])
            self.assertEqual(result['status'], 'Inactive')
            self.assertIsNone(result['ping'])

    async def test_scan_ports_open_closed(self):
        async def fake_open_connection(ip, port):
            class FakeWriter:
                async def wait_closed(self): pass
                def close(self): pass
            if port == 22:
                return (None, FakeWriter())
            else:
                raise ConnectionRefusedError
        with patch('asyncio.open_connection', side_effect=fake_open_connection):
            ports = await scan_ports('192.168.1.1', [22, 80])
            self.assertIn(22, ports)
            self.assertNotIn(80, ports)

    async def test_scan_ips_from_range(self):
        with patch('src.net_scanner.scanner.scan_ip', return_value={'ip': '192.168.1.1', 'status': 'Active', 'ping': 5, 'open_ports': []}):
            results = await scan_ips_from_range('192.168.1.0/30', [])
            self.assertEqual(len(results), 2)

    async def test_scan_ips_from_file(self):
        with patch('builtins.open', unittest.mock.mock_open(read_data='192.168.1.1\n10.0.0.1\n')):
            with patch('src.net_scanner.scanner.scan_ip', return_value={'ip': '192.168.1.1', 'status': 'Active', 'ping': 5, 'open_ports': []}):
                results = await scan_ips_from_file('ip_list.txt', [])
                self.assertEqual(len(results), 2)

if __name__ == '__main__':
    unittest.main()
