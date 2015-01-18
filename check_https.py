import collections
import logging
import json
import queue
import random
import re
import socket
import ssl
import sys
import threading
import time

from http.client import HTTPConnection, HTTPSConnection, HTTPException

import jinja2

PARALLELISM = 8

log = logging.getLogger("check_https")


class Check:

    def __init__(self):
        pass

    def succeed(self, desc):
        self.failed = False
        self.icon = "good"
        self.description = desc

    def fail(self, desc):
        self.failed = True
        self.icon = "bad"
        self.description = desc

def check_one_site(site):
    domain = site["domain"]
    log.info("Checking {}".format(domain))

    site["status"] = "bad"
    site["checks"] = checks = []
    good_connection = Check()
    checks.append(good_connection)
    try:
        addrs = socket.getaddrinfo(domain, 443, socket.AF_INET, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        log.warning("DNS lookup for {} failed!".format(domain))
        return
    info = random.choice(addrs)
    sock = socket.socket(info[0], info[1], info[2])
    sock.settimeout(10)
    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    context.options |= ssl.OP_NO_COMPRESSION
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.load_verify_locations("moz-certs.pem")
    secure_sock = context.wrap_socket(sock, server_hostname=domain)
    try:
        secure_sock.connect(info[4])
    except ConnectionRefusedError:
        good_connection.fail("Nothing is listening on port 443.")
        return
    except socket.timeout:
        good_connection.fail("<code>connect()</code> to port 443 times out.")
        return
    except ssl.SSLError as e:
        if e.reason == "CERTIFICATE_VERIFY_FAILED":
            desc = "Certificate not trusted by Mozilla cert store."
        else:
            desc = "A TLS-related error ({}) occurs when trying to connect.".format(e.reason)
        good_connection.fail(desc)
        return
    except ssl.CertificateError:
        good_connection.fail("Certificate hostname verification fails.")
        return
    good_connection.succeed("A verified TLS connection can be established. "
                            "(<a href=\"https://www.ssllabs.com/ssltest/analyze.html?d={}\">SSL Labs report</a>)".format(domain))

    mediocre = False

    https_load = Check()
    checks.append(https_load)
    http = HTTPSConnection(domain, context=context)
    http.sock = secure_sock
    try:
        http.request("GET", "/")
        resp = http.getresponse()
        if resp.status in (301, 302, 303, 307):
            redirect_to_http = resp.getheader("Location").startswith("http://")
            if redirect_to_http:
                https_load.fail("The HTTPS site redirects to HTTP.")
                return
        elif resp.status != 200:
            https_load.fail("The HTTPS site returns an error code on request.")
            return
        good_sts = Check()
        checks.append(good_sts)
        sts = resp.getheader("Strict-Transport-Security")
        if sts is not None:
            m = re.search("max-age=(\d+)", sts)
            if m is not None:
                age = int(m.group(1))
                if age >= 2592000:
                    good_sts.succeed("<code>Strict-Transport-Security</code> header is set with a long <code>max-age</code> directive.")
                else:
                    good_sts.fail("<code>Strict-Transport-Security</code> header is set but the <code>max-age</code> is less than 30 days.")
            else:
                good_sts.fail("<code>Strict-Transport-Security</code> header doesn't contain a <code>max-age</code> directive.")
        else:
            good_sts.fail("<code>Strict-Transport-Security</code> header is not set.")
        if good_sts.failed:
            mediocre = True
    except socket.timeout:
        https_load.fail("Requesting HTTPS page times out.")
        return
    finally:
        http.close()
    https_load.succeed("A page can be successfully fetched over HTTPS.")

    http_redirect = Check()
    checks.append(http_redirect)
    http = HTTPConnection(domain)
    try:
        url = "/"
        # Follow all redirects.
        while True:
            http.request("GET", url)
            resp = http.getresponse()
            if resp.status in (301, 302, 303, 307):
                url = resp.getheader("Location")
                resp.close()
                if url.startswith("https://"):
                    http_redirect.succeed("HTTP site redirects to HTTPS.")
                    break
            else:
                http_redirect.fail("HTTP site doesn't redirect to HTTPS.")
                mediocre = True
                break
    except HTTPException:
        http_redirect.fail("Encountered HTTP error while loading HTTP site.")
    finally:
        http.close()

    site["status"] = "mediocre" if mediocre else "good"

def worker(q):
    while True:
        try:
            site = q.get_nowait()
        except queue.Empty:
            return
        try:
            check_one_site(site)
        except Exception:
            log.exception("{} failed!".format(site["domain"]))

def check_sites():
    # Read list of sites.
    with open("sites.json", encoding="utf-8") as fp:
        data = json.load(fp)

    # Some poor man's concurrency.
    q = queue.Queue()
    for cat in data["categories"]:
        for site in cat["sites"]:
            q.put(site)
    n = q.qsize()
    threads = []
    for i in range(PARALLELISM):
        t = threading.Thread(target=worker, args=(q,))
        threads.append(t)
        t.start()
    while not q.empty():
        print("{}/{}".format(n - q.qsize(), n))
        time.sleep(1)
    for t in threads:
        t.join()

    total_status = collections.Counter()
    for cat in data["categories"]:
        cat_status = collections.Counter()
        for site in cat["sites"]:
            cat_status[site["status"]] += 1
        cat["counts"] = cat_status
        total_status.update(cat_status)
    data["counts"] = total_status

    return data

def encode_check(o):
    if not isinstance(o, Check):
        raise TypeError
    return o.__dict__

def main():
    if "--cached" in sys.argv:
        with open("cache.json", "r", encoding="utf-8") as fp:
            data = json.load(fp)
    else:
        data = check_sites()
        with open("cache.json", "w", encoding="utf-8") as fp:
            json.dump(data, fp, default=encode_check)

    # Write out results.
    env = jinja2.Environment()
    with open("index.html.jinja", encoding="utf-8") as fp:
        tmp = env.from_string(fp.read())
    update_time = time.strftime("%Y-%m-%d %H:%MZ", time.gmtime())
    with open("index.html", "w", encoding="utf-8") as fp:
        fp.write(tmp.render(data=data, update_time=update_time))

main()
