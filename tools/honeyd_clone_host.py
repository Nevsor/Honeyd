#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
This tool scans a list of hosts and creates honeyd configuration templates to
to create honeypots that mimic these hosts' OS, TCP/IP stack and services.

To run this script call it with a list of IP addresses, hostnames or network
ranges in CIDR notation.

example:

    $ honeyd_clone_host.py 10.123.321.42 host.localdomain 192.168.123.0/24
"""


import sys
import argparse
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass


@dataclass
class Host:
    "Scan information about a single host."
    address: str
    hostnames: [str]
    most_likely_personality: str
    open_tcp_ports: [int]
    open_udp_ports: [int]
    

def parse_nmap_xml(xml_string):
    """ Extracts informations about hosts from an nmap XML output. """
    
    # Example XML output from nmap: https://nmap.org/book/output-formats-xml-output.html
    # TODO: Maybe use the iterative API of ElementTree (ElementTree.iterparse) to make huge scans more efficient.
    
    root = ET.fromstring(xml_string)
    
    for host_xml in root.findall("host"):
        address = host_xml.find("address").get("addr")
        personality = host_xml.find("os").find("osmatch").get("name")
        host = Host(address, [], personality, [], [])
        for hostname_xml in host_xml.find("hostnames").findall("hostname"):
            host.hostnames.append(hostname_xml.get("name"))
        for port_xml in host_xml.find("ports").findall("port"):
            port_id = port_xml.get("portid")
            protocol = port_xml.get("protocol")
            port_state = port_xml.find("state").get("state")
            if port_state=="open":
                if protocol == "tcp":
                    host.open_tcp_ports.append(port_id)
                if protocol == "udp":
                    host.open_udp_ports.append(port_id)
                    
        yield host
    


def scan_hosts(hosts, nmap_options):
    """ Creates a list of hosts, their "personalities" and open ports. """
    
    # We could also use the package python3-nmap here, but I do not want to add a dependency to save a few lines of code.
    scan_result_xml = subprocess.run(
        ["nmap", "-O", "-oX", "-", nmap_options, *hosts], capture_output=True, check=False, shell=True
    ).stdout
    
    yield from parse_nmap_xml(scan_result_xml)


def main(arguments):
    """ Parses arguments and clone target hosts. """
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "target_hosts",
        help="host to clone",
        metavar="TARGET",
        type=ascii,
        nargs="+",
    )
    parser.add_argument(
        "-o",
        "--outdir",
        help="output directory",
        type=Path,
        default=Path(),
    )
    parser.add_argument(
        "-n",
        "--nmap_options",
        help="options to pass to nmap for the scan",
        default="",
    )

    args = parser.parse_args(arguments)

    for host in scan_hosts(args.target_hosts, args.nmap_options):
        print(host)


if __name__ == "__main__":
    #sys.exit(main(sys.argv[1:]))
    main(sys.argv[1:])
