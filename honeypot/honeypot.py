#!/usr/bin/env python3
"""Starter template for the honeypot assignment."""

import logging
import os
import time
import paramiko
import socket
import threading

LOG_PATH = "/app/logs/honeypot.log"
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


def run_honeypot():
  logger = logging.getLogger("Honeypot")
  logger.info("Honeypot starter template running.")
  logger.info("TODO: Implement protocol simulation, logging, and alerting.")

  server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  server_socket.bind(('0.0.0.0', HONEYPOT_PORT))
  server_socket.listen(5)
  host_key = paramiko.RSAKey.generate(2048)

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
