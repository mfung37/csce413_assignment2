#!/usr/bin/env python3
"""
Port Scanner - Starter Template for Students
Assignment 2: Network Security

This is a STARTER TEMPLATE to help you get started.
You should expand and improve upon this basic implementation.

TODO for students:
1. Implement multi-threading for faster scans
2. Add banner grabbing to detect services
3. Add support for CIDR notation (e.g., 192.168.1.0/24)
4. Add different scan types (SYN scan, UDP scan, etc.)
5. Add output formatting (JSON, CSV, etc.)
6. Implement timeout and error handling
7. Add progress indicators
8. Add service fingerprinting
"""

import socket
import argparse
import re
import ipaddress
import concurrent.futures

def scan_port(target, port, timeout=1.0):
  """
  Scan a single port on the target host

  Args:
    target (str): IP address or hostname to scan
    port (int): Port number to scan
    timeout (float): Connection timeout in seconds

  Returns:
    bool: True if port is open, False otherwise
  """
  try:
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.settimeout(timeout) 
    client.connect((target, port))
    client.close()
    return True

  except (socket.timeout, ConnectionRefusedError, OSError):
    return False


def scan_range(target, start_port, end_port, threads: int):
  """
  Scan a range of ports on the target host

  Args:
    target (str): IP address or hostname to scan
    start_port (int): Starting port number
    end_port (int): Ending port number
    threads (int): Number of threads to scan the port range

  Returns:
    list: List of open ports
  """
  open_ports = []

  print(f"[*] Scanning {target} from port {start_port} to {end_port}")

  with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
    # run the threads
    future_to_port = {
      executor.submit(scan_port, target, port): port 
      for port in range(start_port, end_port + 1)
    }

    # go through the results and add these ports
    for future in concurrent.futures.as_completed(future_to_port):
      port = future_to_port[future]
      try:
        if future.result():
          open_ports.append(port)
      except Exception as e:
        print(f" [!] Error scanning port {port} on target {target}: {e}")

  return sorted(open_ports)

def handle_parsing_cmdline():
  # Basic parsing of command-line arguments
  parser = argparse.ArgumentParser(description="Basic port scanner")

  parser.add_argument('--target', type=str, required=True,
            help='Target IP address, optionally with CIDR')
  parser.add_argument('--ports', type=str, required=True,
            help='Port range ex: 1-65535')
  parser.add_argument('--threads', type=int, default=1,
            help='Number of threads')
            
  args = parser.parse_args()

  return args

def input_validation(args):
  # valid target
  valid_ip = lambda x: map(lambda y: 0 <= int(y) <= 255, x.split('.'))
  if re.match(r'^(\d{,3}\.){3}\d{,3}$', args.target) and valid_ip(args.target):
    targets = [args.target]
  elif re.match(r'^(\d{,3}\.){3}\d{,3}/\d{,2}$', args.target):
    try:
      targets = ipaddress.IPv4Network(args.target)
    except:
      print('main.py: error: --target incorrect cidr format')
      exit(-1)
  else:
    exit(-1)

  # valid port range
  if not re.match(r'^\d+-\d+$', args.ports):
    print('main.py: error: --ports incorrect format')
    exit(-1)

  start_port, end_port = list(map(int, args.ports.split('-')))

  return targets, start_port, end_port

def main():
  """Main function"""

  args = handle_parsing_cmdline()
  targets, start_port, end_port = input_validation(args)
  print(f"[*] Starting port scan on {args.target}")
  print(f"[*] This may take a while...")
  
  target_open_ports = {}
  for target in targets:
    target_open_ports[target] = scan_range(str(target), start_port, end_port, args.threads)

  print(f"\n[+] Scan complete!")
  print(f"[+] Found {sum(map(len, target_open_ports.values()))} open ports:")
  for target, ports in target_open_ports.items():
    print(f"Target {target}")
    for port in ports:
      print(f"  Port {port}: open")

if __name__ == "__main__":
  main()
