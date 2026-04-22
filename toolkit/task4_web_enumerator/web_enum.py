#!/usr/bin/env python3
# (task 4 web reconnaissance)
# (Harry Corcoran 01/04/2026)

import argparse
import csv
import logging
import sys
import requests
from bs4 import BeautifulSoup, Comment


class webscanner:
    # areas to probe
    dirs = ["/robots.txt", "/admin", "/phpmyadmin", "/.git"]

    def __init__(self, url, t=10.0, v=False, file_path=None):
        self.url = url.rstrip('/')
        self.t = t
        self.v = v
        self.file_path = file_path
        self.logger = self.set_up_logs()
        self.sess = requests.Session()
        self.sess.headers.update({'User-Agent': 'web-scanner-task4'})

    def set_up_logs(self):
        # simple terminal logging
        logger = logging.getLogger(__name__)
        lvl = logging.DEBUG if self.v else logging.INFO
        logger.setLevel(lvl)
        h = logging.StreamHandler(sys.stdout)
        h.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%d/%m/%y %H:%M:%S'))
        logger.addHandler(h)
        return logger

    def pull(self, path=""):
        # get page with set timeout
        link = self.url + path
        try:
            r = self.sess.get(link, timeout=self.t)
            return r, None
        except Exception as e:
            return None, str(e)

    def scan_headers(self):
        # get server info
        r, err = self.pull()
        if err: return {}

        heads = {}
        for k in ['Server', 'X-Powered-By']:
            val = r.headers.get(k)
            if val: heads[k] = val
        return heads

    def find_comments(self):
        # remove dev comments
        r, err = self.pull()
        if err: return []

        soup = BeautifulSoup(r.text, 'html.parser')
        found = []
        for c in soup.find_all(string=lambda s: isinstance(s, Comment)):
            txt = c.strip()
            if txt: found.append(txt)
        return found

    def hit_paths(self, paths=None):
        # check status codes
        todo = paths if paths else self.dirs
        hits = []
        for p in todo:
            r, err = self.pull(p)
            if err:
                hits.append((p, 0, err))
            else:
                hits.append((p, r.status_code, r.reason))
        return hits

    def save_to_csv(self, heads, comments, hits):
        # save to csv if wanted
        if not self.file_path: return
        try:
            with open(self.file_path, 'w', newline='', encoding='utf-8') as f:
                w = csv.writer(f)
                w.writerow(['type', 'item', 'status', 'info'])
                for k, v in heads.items(): w.writerow(['HEAD', k, v, ''])
                for c in comments: w.writerow(['COMM', 'N/A', c, ''])
                for path, code, msg in hits:
                    s = code if code != 0 else "ERR"
                    w.writerow(['PATH', path, s, msg])
            self.logger.info(f"file saved: {self.file_path}")
        except Exception as e:
            self.logger.error(f"csv failed to save : {e}")

    def print_output(self, heads, comments, hits):
        # to match like requirements of the assignment brief
        print("\n[HEADERS]")
        if heads:
            for k, v in heads.items(): print(f"{k}: {v}")
        else:
            print("none found.")

        print("\n[COMMENTS]")
        if comments:
            for c in comments: print(c)
        else:
            print("none found.")

        print("\n[SENSITIVE PATHS]")
        for p, code, msg in hits:
            if code == 0:
                print(f"{p}: ERROR - {msg}")
            else:
                print(f"{p}: {code} {msg}")

    def go(self, usr_paths=None):
        # run scan
        self.logger.info(f"scanning: {self.url}")
        h_data = self.scan_headers()
        c_data = self.find_comments()
        p_data = self.hit_paths(usr_paths)

        self.print_output(h_data, c_data, p_data)
        self.save_to_csv(h_data, c_data, p_data)


def get_args():
    p = argparse.ArgumentParser(description="web recon task4 tool")
    p.add_argument("url", help="target url")
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument("--paths", "-p", help="extra paths (csv)")
    p.add_argument("--csv", "-c", help="output file")
    return p.parse_args()


def main():
    a = get_args()
    u_paths = [p.strip() for p in a.paths.split(',') if p.strip()] if a.paths else None

    tool = webscanner(url=a.url, t=a.timeout, v=a.verbose, file_path=a.csv)
    try:
        tool.go(usr_paths=u_paths)
    except KeyboardInterrupt:
        print("\n program ended.")
        sys.exit(1)


if __name__ == "__main__":
    main()