import argparse
import collections
import concurrent.futures
import errno
import logging
import json
import random
import re
import socket
import ssl
import time

from http.client import HTTPConnection, HTTPSConnection, HTTPException
from urllib.parse import urlsplit

import jinja2

PARALLELISM = 16
USER_AGENT = "HTTPSWatch Bot (https://httpswatch.com)"

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

    context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3

    # Some platforms (OS X) do not have OP_NO_COMPRESSION
    if hasattr(ssl, "OP_NO_COMPRESSION"):
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
    except OSError as e:
        error_name = errno.errorcode[e.errno]
        good_connection.fail("<code>connect()</code> returns with error {}.".format(error_name))
        return
    good_connection.succeed("A verified TLS connection can be established. "
                            "(<a href=\"https://www.ssllabs.com/ssltest/analyze.html?d={}\">SSL Labs report</a>)".format(domain))

    mediocre = False

    https_load = Check()
    checks.append(https_load)
    http = HTTPSConnection(domain, context=context)
    http.sock = secure_sock
    try:
        url = "/"
        # Follow all redirects.
        while True:
            http.request("GET", url, headers={"User-Agent": USER_AGENT})
            resp = http.getresponse()
            if resp.status in (301, 302, 303, 307):
                url = resp.getheader("Location")
                resp.read()
                resp.close()
                if url.startswith("http://"):
                    https_load.fail("The HTTPS site redirects to HTTP.")
                    return
            elif resp.status != 200:
                https_load.fail("The HTTPS site returns an error code on request.")
                return
            else:
                break
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
    except OSError as e:
        err_msg = errno.errorcode[e.errno]
        https_load.fail("Encountered error ({}) while loading HTTPS site.".format(err_msg))
        return
    finally:
        http.close()
    https_load.succeed("A page can be successfully fetched over HTTPS.")

    http_redirect = Check()
    checks.append(http_redirect)
    http = HTTPConnection(domain)
    try:
        path = "/"
        # Follow all redirects.
        while True:
            http.request("GET", path, headers={"User-Agent": USER_AGENT})
            resp = http.getresponse()
            if resp.status in (301, 302, 303, 307):
                url = urlsplit(resp.getheader("Location"))
                resp.close()
                if url.scheme == "https":
                    http_redirect.succeed("HTTP site redirects to HTTPS.")
                    break
                if url.netloc and url.netloc != domain:
                    http_redirect.fail("HTTP site redirects to a different domain.")
                    break
                path = url.path
                if not path.startswith("/"):
                    url = "/" + url
            else:
                http_redirect.fail("HTTP site doesn't redirect to HTTPS.")
                mediocre = True
                break
    except HTTPException:
        http_redirect.fail("Encountered HTTP error while loading HTTP site.")
        return
    except OSError as e:
        err_msg = errno.errorcode[e.errno]
        http_redirect.fail("Encountered error ({}) while loading HTTP site.".format(err_msg))
        return
    finally:
        http.close()

    site["status"] = "mediocre" if mediocre else "good"


def check_sites(sites_file):
    # Read list of sites.
    with open(sites_file, encoding="utf-8") as fp:
        data = json.load(fp)

    futures = []
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=PARALLELISM)
    with executor:
        for cat in data["categories"]:
            for site in cat["sites"]:
                futures.append(executor.submit(check_one_site, site))
        while True:
            done, not_done = concurrent.futures.wait(futures, timeout=1)
            print("{}/{}".format(len(done), len(done) + len(not_done)))
            if not not_done:
                break
        for f in futures:
            # This will raise an exception if check_one_site did.
            f.result()

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
    parser = argparse.ArgumentParser()
    parser.add_argument("--cached", action="store_true")
    parser.add_argument("sites", default="sites.json", nargs="?")

    args = parser.parse_args()

    if args.cached:
        with open("cache.json", "r", encoding="utf-8") as fp:
            data = json.load(fp)
    else:
        data = check_sites(args.sites)
        with open("cache.json", "w", encoding="utf-8") as fp:
            json.dump(data, fp, default=encode_check)

    # Write out results.
    env = jinja2.Environment()
    with open("index.html.jinja", encoding="utf-8") as fp:
        tmp = env.from_string(fp.read())
    update_time = time.strftime("%Y-%m-%d %H:%MZ", time.gmtime())
    with open("index.html", "w", encoding="utf-8") as fp:
        fp.write(tmp.render(data=data, update_time=update_time))


if __name__ == "__main__":
    main()
