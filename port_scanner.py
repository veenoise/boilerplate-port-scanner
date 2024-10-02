import socket
import nmap 
import validators
from tabulate import tabulate
from common_ports import ports_and_services

def get_open_ports(target, port_range, verbose = False):
    open_ports = []

    try:
        if validators.ipv4(target) or validators.ipv6(target):    
            is_valid_ip = True

        elif validators.hostname(target):
            is_valid_domain = True

        else:
            raise ValueError("Invalid IP")

    except ValueError as ve:
        return "Error: Invalid IP address"

    except socket.gaierror as e:
        return "Error: Invalid hostname"

    port = f'{port_range[0]}-{port_range[1]}'

    nm = nmap.PortScanner()
    nm.scan(target, port)

    try:
        for scanned_port in nm[nm.all_hosts()[0]]["tcp"]:
            if nm[nm.all_hosts()[0]]["tcp"][scanned_port]["state"] == "open":
                open_ports.append(scanned_port)
        if not verbose:
            return(open_ports)
        else:
            ip_addr = ""
            domain = ""
            port_with_name = [[i, ports_and_services[i]] for i in open_ports]
            table_head = ['PORT ', 'SERVICE']
            try:
                ip_addr_and_domain = socket.gethostbyaddr(target)
                ip_addr = ip_addr_and_domain[2][0]
                domain = ip_addr_and_domain[0]
            except socket.herror as se:
                domain = target

            return f"Open ports for {domain}{f' ({ip_addr})' if ip_addr != "" else ""}\n{tabulate(port_with_name, table_head, tablefmt="plain", colalign=("left", "left"))}"

    except IndexError as ee:
        return "Error: Invalid hostname"
