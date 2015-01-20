#!/usr/bin/env python3
import argparse
import collections
import concurrent.futures
import errno
import logging
import json
import os
import random
import re
import shutil
import socket
import ssl
import time

from http.client import HTTPConnection, HTTPSConnection, HTTPException
from urllib.parse import urlsplit

import jinja2

PARALLELISM = 16
USER_AGENT = "HTTPSWatch Bot (https://httpswatch.com)"
ANALYTICS = """<script>
(function(i,s,o,g,r,a,m){i['GoogleAnalyticsObject']=r;i[r]=i[r]||function(){
(i[r].q=i[r].q||[]).push(arguments)},i[r].l=1*new Date();a=s.createElement(o),
m=s.getElementsByTagName(o)[0];a.async=1;a.src=g;m.parentNode.insertBefore(a,m)
})(window,document,'script','//www.google-analytics.com/analytics.js','ga');

ga('create', 'UA-342043-4', 'auto');
ga('send', 'pageview');
</script>
"""

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


class Not200(Exception):

    def __init__(self, status):
        super(Exception, self).__init__()
        self.status = status


def fetch_through_redirects(http, stop=None):
    path = "/"
    url = None
    while True:
        http.request("GET", path, headers={"User-Agent": USER_AGENT})
        resp = http.getresponse()
        if resp.status in (301, 302, 303, 307):
            url = urlsplit(resp.getheader("Location"))
            if stop is not None and stop(url):
                break
            resp.read()
            resp.close()
            if url.netloc and url.netloc != http.host:
                # Probably should actually handle this...
                raise ValueError("Site redirects to a different domain.")
            path = url.path
            if not path.startswith("/"):
                path = "/" + path
            continue
        if resp.status != 200:
            raise Not200(resp.status)
        break
    return url, resp


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
        def stop_on_http_or_domain_change(url):
            return url.scheme == "http" or (url.netloc and url.netloc != domain)
        final, resp = fetch_through_redirects(http, stop_on_http_or_domain_change)
        if final is not None and final.scheme == "http":
            https_load.fail("The HTTPS site redirects to HTTP.")
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
    except Not200 as e:
        https_load.fail("The HTTPS site returns an error status ({}) on request.".format(e.status))
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
        def stop_on_https(url):
            return url.scheme == "https"
        final, resp = fetch_through_redirects(http, stop_on_https)
        if final is not None and final.scheme == "https":
            http_redirect.succeed("HTTP site redirects to HTTPS.")
        else:
            http_redirect.fail("HTTP site doesn't redirect to HTTPS.")
            mediocre = True
    except HTTPException:
        http_redirect.fail("Encountered HTTP error while loading HTTP site.")
        return
    except Not200 as e:
        http_redirect.fail("The HTTP site returns an error status ({}) on request.".format(e.status))
        return
    except OSError as e:
        err_msg = errno.errorcode[e.errno]
        http_redirect.fail("Encountered error ({}) while loading HTTP site.".format(err_msg))
        return
    finally:
        http.close()

    site["status"] = "mediocre" if mediocre else "good"


def regenerate_everything():
    with open("config/meta.json", "r", encoding="utf-8") as fp:
        meta = json.load(fp)
    futures = []
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=PARALLELISM)
    for listing in meta["listings"]:
        if "external" in listing:
            continue
        with open("config/{}.json".format(listing["shortname"]), encoding="utf-8") as fp:
            listing["data"] = json.load(fp)
        for cat in listing["data"]["categories"]:
            for site in cat["sites"]:
                futures.append(executor.submit(check_one_site, site))
    with executor:
        while True:
            done, not_done = concurrent.futures.wait(futures, timeout=1)
            print("{}/{}".format(len(done), len(done) + len(not_done)))
            if not not_done:
                break
        for f in futures:
            # This will raise an exception if check_one_site did.
            f.result()

    for listing in meta["listings"]:
        if "external" in listing:
            continue
        for cat in listing["data"]["categories"]:
            cat_status = collections.Counter()
            for site in cat["sites"]:
                cat_status[site["status"]] += 1
            cat["counts"] = cat_status

    return meta


def encode_check(o):
    if not isinstance(o, Check):
        raise TypeError
    return o.__dict__


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cached", action="store_true")

    args = parser.parse_args()

    if args.cached:
        with open("cache.json", "r", encoding="utf-8") as fp:
            meta = json.load(fp)
    else:
        meta = regenerate_everything()
        with open("cache.json", "w", encoding="utf-8") as fp:
            json.dump(meta, fp, default=encode_check)

    # Write out results.
    env = jinja2.Environment(loader=jinja2.FileSystemLoader("templates"))
    env.globals["analytics"] = ANALYTICS
    env.globals["update_time"] = time.strftime("%Y-%m-%d %H:%MZ", time.gmtime())
    env.globals["meta"] = meta
    try:
        os.mkdir("out")
    except FileExistsError:
        pass
    with open("out/about.html", "w", encoding="utf-8") as fp:
        fp.write(env.get_template("about.html.jinja").render())
    listing_tmp = env.get_template("listing.html.jinja")
    for listing in meta["listings"]:
        if "external" in listing:
            continue
        out_fn = "out/{}.html".format(listing["shortname"])
        with open(out_fn, "w", encoding="utf-8") as fp:
            fp.write(listing_tmp.render(listing=listing))
        if meta["default_page"] == listing["shortname"]:
            shutil.copy(out_fn, "out/index.html")


if __name__ == "__main__":
    main()
