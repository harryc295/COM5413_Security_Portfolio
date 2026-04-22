#!/usr/bin/env python3
# (task 1 parser / auth log tool for linux)
# (Harry Corcoran 31/03/2026)

import argparse
import csv
import hashlib
import re
import sys
import json
import os

# (files no larger than 100mb so no memory issues with huge logs )
MAX_SIZE = 100 * 1024 * 1024


class logparser:
    def __init__(self, debug=False):
        self.trys = []
        self.seen = set()
        self.debug = debug

        # (patterns i used to find usernames ips and failed password attempts for invalid users)
        self.regexes = [
            r'Failed password for (?:(?:invalid user )?(\S+)).*?from (\d+\.\d+\.\d+\.\d+)',
            r'Invalid user (\S+).*?from (\d+\.\d+\.\d+\.\d+)',
            r'authentication failure.*?rhost=(\d+\.\d+\.\d+\.\d+).*?user=(\S+)',
            r'pam_unix\(.*?\): authentication failure.*?rhost=(\d+\.\d+\.\d+\.\d+).*?user=(\S+)'
        ]

    def parse_file(self, fname):
        # (checking file is there)
        if not (os.path.exists(fname) and os.path.isfile(fname)):
            sys.stderr.write(f"([Error] file not found]): {fname}\n")
            sys.exit(1)

        if os.path.getsize(fname) > MAX_SIZE:
            sys.stderr.write("([Error] File too big)\n")
            return []

        if self.debug:
            print(f"([Debug] Parsing file on ): {fname}")

        try:
            with open(fname, 'r', errors='ignore') as fh:
                for txt in fh:
                    txt = txt.strip()
                    if not txt: continue

                    for r in self.regexes:
                        m = re.search(r, txt, re.I)
                        if m:
                            groups = m.groups()
                            # (making the output standard if group 1 or group 2 is the ip add)
                            if "." in groups[0]:
                                ip, usr = groups[0], groups[1]
                            else:
                                usr, ip = groups[0], groups[1]

                            if not all(0 <= int(v) <= 255 for v in ip.split('.') if v.isdigit()):
                                continue

                            usr = usr.strip('"\'').strip()

                            # (scrape timestamp from start of log line)
                            ts = "Unknown"
                            date_m = re.search(r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', txt)
                            if date_m: ts = date_m.group(1)

                            # (make set ids to avoid duplicate inputs in the csv via md5 hashes)
                            uid = hashlib.md5(f"{ts}{ip}{usr}".encode()).hexdigest()[:8]

                            if uid not in self.seen:
                                self.seen.add(uid)
                                self.trys.append({
                                    "Timestamp": ts,
                                    "IP_Address": ip,
                                    "User_Account": usr
                                })
                                if self.debug:
                                    print(f"(match found): {usr} @ {ip}")
                            break
        except Exception as err:
            sys.stderr.write(f"([Error] failure during file processing ): {err}\n")
            sys.exit(1)

        return self.trys

    def save_results(self, out, as_json=False):
        if not self.trys:
            print("(scan finished no suspicious failures )")
            return

        try:
            # (benji protocol so csv header must be exact for the automatic grader )
            with open(out, 'w', newline='') as f:
                w = csv.DictWriter(f, fieldnames=["Timestamp", "IP_Address", "User_Account"])
                w.writeheader()
                w.writerows(self.trys)

            if as_json:
                j_out = out.replace('.csv', '.json')
                with open(j_out, 'w') as f:
                    report = self.get_report()
                    json.dump({"summary": report, "data": self.trys}, f, indent=2)

            print(f"(saved and exported to): {out}")
        except Exception as e:
            sys.stderr.write(f"([Error] coudnt write to output file ): {e}\n")
            sys.exit(1)

    def get_report(self):
        # (totals for summary)
        ips, users = {}, {}
        for val in self.trys:
            ips[val['IP_Address']] = ips.get(val['IP_Address'], 0) + 1
            users[val['User_Account']] = users.get(val['User_Account'], 0) + 1

        return {
            "total": len(self.trys),
            "top_ips": sorted(ips.items(), key=lambda v: v[1], reverse=True)[:5],
            "top_users": sorted(users.items(), key=lambda v: v[1], reverse=True)[:5]
        }


def main():
    ap = argparse.ArgumentParser(description="(automated log analysis and extractor )")
    ap.add_argument("input_file", help="(the path to the auth file)")
    ap.add_argument("-o", "--output", default="suspects.csv", help="(where to save results [default: suspects.csv")
    ap.add_argument("-j", "--json", action="store_true", help="(export a seccondary json report)")
    ap.add_argument("-s", "--summary", action="store_true", help="(show top attacking ips in terminal window)")
    ap.add_argument("-v", "--verbose", action="store_true", help="(prints every match in real time)")

    cmd = ap.parse_args()

    p = logparser(debug=cmd.verbose)
    p.parse_file(cmd.input_file)
    p.save_results(cmd.output, cmd.json)

    if cmd.summary:
        r = p.get_report()
        print("\n(statistics overview)")
        print(f"(total unique attacks found): {r['total']}")
        if r['top_ips']:
            print(f"(top threat actor ip): {r['top_ips'][0][0]} ({r['top_ips'][0][1]} times)")


if __name__ == "__main__":
    main()