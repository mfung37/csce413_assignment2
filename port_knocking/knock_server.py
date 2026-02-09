#!/usr/bin/env python3
"""Starter template for the port knocking server."""

import argparse
import logging
import socket
import time
import threading
import subprocess
import select

DEFAULT_KNOCK_SEQUENCE = [1234, 5678, 9012]
DEFAULT_PROTECTED_PORT = 2222
DEFAULT_SEQUENCE_WINDOW = 10.0


def setup_logging():
  logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
  )

def drop_all_protected_port(protected_port):
  """Drop all to protected port by default"""
  logging.info("Dropping on firewall on port %s", protected_port)

  try:
    cmd = [
      "iptables", "-I", "INPUT", "1",
      "-p", "tcp",
      "--dport", str(protected_port),
      "-j", "DROP",
    ]
    subprocess.run(cmd, check=True)
  except subprocess.CalledProcessError as e:
    logging.error(f"Failed to drop port: {e}")

def open_protected_port(ip, protected_port):
  """Open the protected port using firewall rules."""
  logging.info("Opening firewall for source ip %s on port %s", ip, protected_port)

  try:
    cmd = [
      "iptables", "-I", "INPUT", "1",
      "-s", ip,
      "-p", "tcp",
      "--dport", str(protected_port),
      "-j", "ACCEPT",
    ]
    subprocess.run(cmd, check=True)
  except subprocess.CalledProcessError as e:
    logging.error(f"Failed to open port: {e}")

def close_protected_port(ip, protected_port):
  """Close the protected port using firewall rules."""
  logging.info("Close firewall for source ip %s on port %s", ip, protected_port)

  try:
    cmd = [
      "iptables", "-D", "INPUT",
      "-s", ip,
      "-p", "tcp",
      "--dport", str(protected_port),
      "-j", "ACCEPT",
    ]
    subprocess.run(cmd, check=True)
  except subprocess.CalledProcessError as e:
    logging.error(f"Failed to close port: {e}")

def listen_for_knocks(sequence, window_seconds, protected_port):
  """Listen for knock sequence and open the protected port."""
  logger = logging.getLogger("KnockServer")
  logger.info("Listening for knocks: %s", sequence)
  logger.info("Protected port: %s", protected_port)

  # TODO: Create UDP or TCP listeners for each knock port.
  # TODO: Track each source IP and its progress through the sequence.
  # TODO: Enforce timing window per sequence.
  # TODO: On correct sequence, call open_protected_port().
  # TODO: On incorrect sequence, reset progress.

  # create a socket for each port of sequence to listen for the knocks
  knock_sockets = {}
  for port in sequence:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', port))
    sock.setblocking(False)
    knock_sockets[sock] = port

  # stores each client along with progression and start of sequence
  client_states = {}

  # main loop to listen for knocks
  while True:
    # uses select to get ports that have actually recieved something
    readable, _, _ = select.select(knock_sockets.keys(), [], [], 1.0)

    current_time = time.time()

    for sock in readable:
      # recv but only keep where it came from
      _, (ip, _) = sock.recvfrom(1024)
      target_port = knock_sockets[sock]

      logger.info("Knocked from ip %s on port %s", ip, target_port)

      state = client_states.setdefault(ip, {'index': 0, 'start_time': current_time})

      # took too long for the sequence
      if state['start_time'] + window_seconds < current_time:
        logger.warning("Sequence took too long to complete. Resetting...")
        client_states.pop(ip)
        continue

      # correct knock
      if target_port == sequence[state['index']]:
        if state['index'] == 0:
          state['start_time'] = current_time
          
        state['index'] += 1

        # complete sequence
        if state['index'] == len(sequence):
          logger.info(f"Opening port {protected_port} for {ip}.")
          open_protected_port(ip, protected_port)

          # reset sequence if need to do it again
          client_states.pop(ip)
      else:
        logger.warning(f"Incorrect sequence from {ip}. Resetting...")
        client_states.pop(ip)

def start_service(protected_port):
  """Runs python basic http.server for the port"""
  logger = logging.getLogger("KnockServer")
  logger.info("Starting service on %s", protected_port)

  with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    try:
      server.bind(('0.0.0.0', protected_port))
      server.listen(5)

      while True:
        conn, addr = server.accept()
        with conn:
          logger.info("Successful connection with %s", addr)
          conn.send(b"Success")

    except Exception as e:
      logger.error("Failed to start service:", e)

def parse_args():
  parser = argparse.ArgumentParser(description="Port knocking server starter")
  parser.add_argument(
    "--sequence",
    default=",".join(str(port) for port in DEFAULT_KNOCK_SEQUENCE),
    help="Comma-separated knock ports",
  )
  parser.add_argument(
    "--protected-port",
    type=int,
    default=DEFAULT_PROTECTED_PORT,
    help="Protected service port",
  )
  parser.add_argument(
    "--window",
    type=float,
    default=DEFAULT_SEQUENCE_WINDOW,
    help="Seconds allowed to complete the sequence",
  )
  return parser.parse_args()


def main():
  args = parse_args()
  setup_logging()

  try:
    sequence = [int(port) for port in args.sequence.split(",")]
  except ValueError:
    raise SystemExit("Invalid sequence. Use comma-separated integers.")

  # starts service on separate thread
  t = threading.Thread(target=start_service, args=(args.protected_port,), daemon=True)
  t.start()

  # close port to all users
  drop_all_protected_port(args.protected_port)

  listen_for_knocks(sequence, args.window, args.protected_port)


if __name__ == "__main__":
  main()
