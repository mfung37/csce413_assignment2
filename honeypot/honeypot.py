#!/usr/bin/env python3
"""Starter template for the honeypot assignment."""

import logging
import os
import time
import paramiko
import socket
import threading

LOG_PATH = "/app/logs/honeypot.log"
KEY_FILE = "/app/logs/host.key" # persistant as host shares the logs volume
HONEYPOT_PORT = 22

# A dummy interface to handle authentication logic
class HoneypotServer(paramiko.ServerInterface):
  def check_auth_password(self, username, password):
    print(f"Login attempt: {username} / {password}")
    return paramiko.AUTH_FAILED

def setup_logging():
  os.makedirs("/app/logs", exist_ok=True)
  logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler(LOG_PATH), logging.StreamHandler()],
  )

def get_host_key():
  if os.path.exists(KEY_FILE):
    # Load the existing key
    return paramiko.RSAKey.from_private_key_file(KEY_FILE)
  else:
    # Generate and save a new key once
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(KEY_FILE)
    return key

def run_honeypot():
  logger = logging.getLogger("Honeypot")
  logger.info("Honeypot starting")

  try:
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', HONEYPOT_PORT))
    server_socket.listen(5)
  except Exception as e:
    logger.error("Failed to start honeypot:", e)
    return

  host_key = get_host_key()

  while True:
    conn, addr = server_socket.accept()

    logger.info(f"Connection from {addr}")

    transport = paramiko.Transport(conn)
    transport.add_server_key(host_key)
    
    server = HoneypotServer()
    transport.start_server(server=server)

if __name__ == "__main__":
  setup_logging()
  run_honeypot()
