import time
import random
import netifaces
import nmap
import subprocess
import json
from halo import Halo
from tabulate import tabulate
from colorama import Fore, Style, init

class NmapDiscover:
    def __init__(self):
        pass

    def discover(self, interface, ip_range, timeout):
        nm = nmap.PortScanner()
        spinner = Halo(text=f"Discovering hosts on {ip_range}", spinner="dots")
        spinner.start()

        try:
            nm.scan(hosts=ip_range, arguments='-sn', timeout=timeout)

            devices = []
            hosts_list = [(host, nm[host]['status']['state']) for host in nm.all_hosts()]

            for host, status in hosts_list:
                if status == "up":
                    mac = nm[host].get('addresses', {}).get('mac', 'N/A')
                    devices.append({'ip': host, 'mac': mac})

            spinner.succeed("Hosts discovered")
            return devices

        except nmap.nmap.PortScannerTimeout:
            spinner.fail(f"Timeout occurred while scanning {ip_range}")
            return []

class CVEMap:
    def __init__(self):
        init(autoreset=True)

        self.metadata = {
            "Codename": "CVEMap",
            "Description": "CVE scanning utility.",
            "Version": "1.0.0",
            "Author": "Jiten Adhikari <@jitenadk>",
            "License": "BSD 3-Clause",
            "Repository": "https://github.com/jitenadk/CVEMap"
        }

        self.banner = f"""
┏┓┓┏┏┓┳┳┓
┃ ┃┃┣ ┃┃┃┏┓┏┓
┗┛┗┛┗┛┛ ┗┗┻┣┛
           ┛ {self.metadata['Version']}
"""
        self.color = random.choice([Fore.RED, Fore.GREEN, Fore.BLUE])
        self.reset = Style.RESET_ALL

        self.display_banner()
        self.scan_all_interfaces()

    def display_banner(self):
        max_key_length = max(len(key) for key in self.metadata)
        print(f"{self.color}{self.banner}{self.reset}")
        for key, value in self.metadata.items():
            print(f"{self.color}•{self.reset} {key.ljust(max_key_length)} : {value}")
        print()

    def scan_all_interfaces(self):
        interfaces = netifaces.interfaces()
        all_device_results = []

        for interface in interfaces:
            addrs = netifaces.ifaddresses(interface)

            if netifaces.AF_INET in addrs:
                ipv4 = addrs[netifaces.AF_INET][0]
                ip_addr = ipv4['addr']
                netmask = ipv4['netmask']

                if ip_addr.startswith('127.'):
                    continue

                cidr_range = self.calculate_cidr_range(ip_addr, netmask)
                print(f"Scanning interface {interface} with IP Range {cidr_range}...")

                nmapdiscover = NmapDiscover()
                devices = nmapdiscover.discover(interface, cidr_range, timeout=10)

                if not devices:
                    print(f"No devices discovered on {interface}.\n")
                    continue

                devices_list = [[device['ip'], device['mac']] for device in devices]
                print(tabulate(devices_list, headers=["IP Address", "Mac Address"], tablefmt="grid"))
                print()

                for device in devices:
                    device_scan_results = self.scan_device(device['ip'])
                    if device_scan_results:
                        all_device_results.append(device_scan_results)

        if all_device_results:
            print("\n")
            print(tabulate(all_device_results, headers="keys", tablefmt="grid"))
        else:
            print("No devices found or no scans completed.\n")

    def scan_device(self, ip):
        nm = nmap.PortScanner()
        spinner = Halo(text=f"Scanning device :: {ip}", spinner="dots")
        spinner.start()

        try:
            nm.scan(ip, arguments='-A -T4 --min-rate=10000')

            if ip in nm.all_hosts():
                host_info = nm[ip]
                open_ports = self.get_open_ports(host_info)
                os_info = self.get_os_info(host_info)
                services = self.get_services(host_info)
                cve_info = self.get_cve_for_services(services)

                scan_results = {
                    'IP Address': ip,
                    'OS': os_info,
                    'Open Ports': ', '.join(open_ports),
                    'Services': ', '.join(services),
                    'CVEs': ', '.join(cve_info)
                }

                spinner.succeed(f"Scanning completed for {ip}")
                return scan_results

            else:
                spinner.succeed(f"Scanning completed for {ip}")
                return None

        except Exception as e:
            spinner.fail(f"Error scanning {ip}")
            print(f"Error scanning {ip}: {e}")
            return None

    def get_open_ports(self, host_info):
        open_ports = []
        if 'tcp' in host_info:
            for port in host_info['tcp']:
                if host_info['tcp'][port]['state'] == 'open':
                    open_ports.append(str(port))
        return open_ports

    def get_os_info(self, host_info):
        if 'osmatch' in host_info and len(host_info['osmatch']) > 0:
            return host_info['osmatch'][0]['name']
        return 'N/A'

    def get_services(self, host_info):
        services = []
        if 'tcp' in host_info:
            for port in host_info['tcp']:
                if host_info['tcp'][port]['state'] == 'open' and 'name' in host_info['tcp'][port]:
                    service_name = host_info['tcp'][port]['name']
                    service_version = host_info['tcp'][port].get('version', 'Unknown version')
                    if service_version != 'Unknown version':
                        services.append(f"{service_name} {service_version}")
        return services

    def get_cve_for_services(self, services):
        cve_info = []
        for service in services:
            service_name = service.split(" ")[0]
            service_version = service.split(" ")[1] if len(service.split(" ")) > 1 else None
            if service_version:
                cve_info.extend(self.fetch_cve_for_service(service_name, service_version))
        return cve_info

    def fetch_cve_for_service(self, service_name, service_version):
        try:
            query = f"{service_name} {service_version}" if service_version else service_name
            result = subprocess.run(
                ['searchsploit', '-j', query],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            if result.returncode == 0:
                searchsploit_json = json.loads(result.stdout)
                cve_info = []
                for exploit in searchsploit_json.get('RESULTS_EXPLOIT', []):
                    cve_codes = exploit.get('Codes', '')
                    if cve_codes:
                        cve_info.extend(cve_codes.split(';'))
                    else:
                        cve_info.append('N/A')

                if cve_info:
                    return cve_info
                return ['N/A']

            else:
                print(f"[ERROR] SearchSploit failed with error: {result.stderr}")
                return ['N/A']

        except Exception as e:
            print(f"Error using SearchSploit for {service_name}: {e}")
            return ['N/A']

    def calculate_cidr_range(self, ip_addr, netmask):
        ip_bin = self.ip_to_bin(ip_addr)
        netmask_bin = self.ip_to_bin(netmask)
        network_bin = ''.join(['1' if ip_bin[i] == netmask_bin[i] else '0' for i in range(32)])
        network_address = self.bin_to_ip(network_bin)
        cidr_prefix = netmask_bin.count('1')
        return f"{network_address}/{cidr_prefix}"

    def ip_to_bin(self, ip):
        return ''.join(f'{int(octet):08b}' for octet in ip.split('.'))

    def bin_to_ip(self, binary):
        return '.'.join(str(int(binary[i:i + 8], 2)) for i in range(0, 32, 8))

if __name__ == "__main__":
    CVEMap()
