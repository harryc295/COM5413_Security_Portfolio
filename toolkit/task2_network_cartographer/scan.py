#!/usr/bin/env python3
# (task 2 scanner)
# (Harry Corcoran 31/03/2026)

import argparse
import socket
import json
import sys
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed


class Scanner:

    def __init__(self, host, wait=0.5, threads=100, verbose=False):
        # target and scan settings
        self.host = host
        self.wait = wait
        self.threads = threads
        self.verbose = verbose
        self.logger = self._setup_logging()
        self.host_ip = None
        self.open_ports = []

    def _setup_logging(self):
        # log for the terminal
        logger = logging.getLogger(__name__)
        level = logging.DEBUG if self.verbose else logging.INFO
        logger.setLevel(level)

        h = logging.StreamHandler(sys.stdout)
        h.setLevel(level)

        fmt = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s',
                                datefmt='%d/%m/%y %H:%M:%S')
        h.setFormatter(fmt)
        logger.addHandler(h)
        return logger

    def get_ip(self):
        # hostname to ip address
        try:
            self.host_ip = socket.gethostbyname(self.host)
            self.logger.debug(f"Target {self.host} is at {self.host_ip}")
            return True
        except socket.gaierror:
            self.logger.error(f"Couldn't find host: {self.host}")
            return False

    @staticmethod
    def get_port_list(user_ports):
        # convert port string to list for the loop
        ports = []
        if '-' in user_ports:
            try:
                start, end = user_ports.split('-')
                start, end = int(start), int(end)
                if start < 1 or end > 65535 or start > end:
                    raise ValueError
                ports = list(range(start, end + 1))
            except ValueError:
                raise ValueError(f"range error: {user_ports}")
        else:
            try:
                ports = [int(p.strip()) for p in user_ports.split(',') if p.strip()]
            except ValueError:
                raise ValueError(f"list error: {user_ports}")
        return ports

    def try_port(self, p):
        # try connect and grab the banner
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.wait)
            s.connect((self.host_ip, p))

            info = s.recv(2048).decode('utf-8', errors='ignore').strip()
            self.logger.debug(f"port {p} is open")
            return p, info
        except (socket.timeout, ConnectionRefusedError, socket.error):
            return p, None
        finally:
            if s:
                s.close()

    def run(self, ports):
        # starts the threads to run the scan
        self.open_ports = []
        self.logger.info(f"starting the scan on {self.host_ip}...")

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            jobs = {pool.submit(self.try_port, p): p for p in ports}
            for item in as_completed(jobs):
                p, info = item.result()
                if info is not None:
                    self.open_ports.append({"port": p, "banner": info})
                    self.logger.info(f"port has been scanned: {p} | banner: {info[:60]}")

        self.logger.info(f"scan has now finished. {len(self.open_ports)} ports are open.")

    def save_json(self, filepath="recon_results.json"):
        # put the results in a json file
        results = {
            "target": self.host_ip,
            "open_ports": self.open_ports
        }

        print(json.dumps(results, indent=2))

        try:
            with open(filepath, 'w') as f:
                json.dump(results, f, indent=2)
            self.logger.info(f"data was saved to {filepath}")
            return True
        except IOError as e:
            self.logger.error(f"failed to write file: {e}")
            return False


def get_args():
    # command line flags
    cmd = argparse.ArgumentParser(description="network scanner")
    cmd.add_argument("host", help="ip or host to scan")
    cmd.add_argument("--ports", "-p", default="1-1024", help="e.g. 1-1024 or 80,443")
    cmd.add_argument("--wait", "-w", type=float, default=0.5, help="timeout")
    cmd.add_argument("--threads", "-t", type=int, default=100, help="threads to use")
    cmd.add_argument("--verbose", "-v", action="store_true", help="print debug logs")
    cmd.add_argument("--output", "-o", default="recon_results.json", help="filename for results")
    return cmd.parse_args()


def main():
    args = get_args()

    try:
        port_list = Scanner.get_port_list(args.ports)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    # start up the scanner
    myscanner = Scanner(
        host=args.host,
        wait=args.wait,
        threads=args.threads,
        verbose=args.verbose
    )

    if not myscanner.get_ip():
        sys.exit(1)

    # runs control c so it doesnt just spew red text
    try:
        myscanner.run(port_list)
        myscanner.save_json(args.output)
    except KeyboardInterrupt:
        print("\n[!] User stopped the scan (Ctrl+C). Exiting...")
        sys.exit(1)


if __name__ == "__main__":
    main()