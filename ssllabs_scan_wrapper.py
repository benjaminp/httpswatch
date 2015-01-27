#!/usr/bin/env python3
"""Run SSL Labs server test on all of HTTPSWatch's domains."""
import argparse
import json
import re
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("sslscan_binary")
    parser.add_argument("output_file")
    args = parser.parse_args()

    with open("config/meta.json", "r", encoding="utf-8") as fp:
        meta = json.load(fp)
    domains = []
    for listing in meta["listings"]:
        if "external" in listing:
            continue
        with open("config/{}.json".format(listing["shortname"]), encoding="utf-8") as fp:
            listing["data"] = json.load(fp)
        for cat in listing["data"]["categories"]:
            for site in cat["sites"]:
                domains.append(site["domain"])
    p = subprocess.Popen([args.sslscan_binary, "--grade", "--usecache"] + domains, stdout=subprocess.PIPE)
    stdout = p.communicate()[0].decode("ascii").strip()
    results = {}
    r = re.compile("\"(.+)\": \"(.+)\"", re.ASCII)
    for l in stdout.splitlines():
        m = r.match(l)
        g = m.groups()
        results[g[0]] = g[1]
    with open(args.output_file, "w", encoding="utf-8") as fp:
        json.dump(results, fp)


if __name__ == "__main__":
    main()
