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

import certifi
import jinja2
import requests

from lxml import etree, html

PARALLELISM = 16
USER_AGENT = "Mozilla/5.0 compatible HTTPSWatch analyzer (see httpswatch DOT com)"
ANALYTICS = """<script>
(function(i,s,o,g,r,a,m){i['GoogleAnalyticsObject']=r;i[r]=i[r]||function(){
(i[r].q=i[r].q||[]).push(arguments)},i[r].l=1*new Date();a=s.createElement(o),
m=s.getElementsByTagName(o)[0];a.async=1;a.src=g;m.parentNode.insertBefore(a,m)
})(window,document,'script','//www.google-analytics.com/analytics.js','ga');

ga('create', 'UA-342043-4', 'auto');
ga('send', 'pageview');
</script>
"""
META_XPATH = etree.XPath(
    "//meta[not(ancestor::noscript) and re:test(@http-equiv, \"^refresh$\", \"i\")]",
    namespaces={"re": "http://exslt.org/regular-expressions"}
)
MIXED_CONTENT_XPATH = etree.XPath(
    """
    //link[@ref="stylesheet" and starts-with(@href, "http://")] |
    //script[starts-with(@src, "http://")] |
    //img[not(ancestor::noscript) and starts-with(@src, "http://")]
    """
)

log = logging.getLogger("check_https")


class SiteInfo:

    def __init__(self):
        self.domain = None
        self.ssllabs_grade = None
        self.secure_connection_works = None
        self.can_load_https_page = None
        self.mixed_content = None
        self.sts = None
        self.https_redirects_to_http = None
        self.http_redirects_to_https = None
        self.checks = []

    def new_check(self):
        c = Check()
        self.checks.append(c)
        return c


class Check:

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


def fetch_through_redirects(url):
    tree = None
    while True:
        cont = False
        resp = requests.get(
            url,
            verify=certifi.where(),
            headers={"User-Agent": USER_AGENT},
            timeout=10,
            stream=True,
        )
        try:
            if resp.status_code != 200:
                raise Not200(resp.status_code)
            # Convince urllib3 to decode gzipped pages.
            resp.raw.decode_content = True
            tree = html.parse(resp.raw)
        finally:
            resp.close()
        # Check for sneaky <meta> redirects.
        for meta in META_XPATH(tree):
            m = re.match(r"0;\s*url=['\"](.+?)['\"]", meta.get("content"))
            if m is not None:
                url = m.groups()[0]
                cont = True
                break
        if not cont:
            break
    return resp, tree


def has_mixed_content(tree):
    s = MIXED_CONTENT_XPATH(tree)
    return len(s) >= 1


def check_secure_connection(info):
    # Guilty until proven innocent.
    info.secure_connection_works = False
    good_connection = info.new_check()
    try:
        addrs = socket.getaddrinfo(info.domain, 443, socket.AF_INET, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        good_connection.fail("DNS lookup failed.")
        return
    addr_info = random.choice(addrs)
    sock = socket.socket(addr_info[0], addr_info[1], addr_info[2])
    sock.settimeout(10)
    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
    # Some platforms (OS X) do not have OP_NO_COMPRESSION
    context.options |= getattr(ssl, "OP_NO_COMPRESSION", 0)
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.load_verify_locations(certifi.where())
    secure_sock = context.wrap_socket(sock, server_hostname=info.domain)
    try:
        secure_sock.connect(addr_info[4])
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
    finally:
        secure_sock.close()
    msg = "A verified TLS connection can be established. "
    if info.ssllabs_grade is not None:
        grade_msg = "<a href=\"https://www.ssllabs.com/ssltest/analyze.html?d={}\" target=\"_blank\">SSL Labs grade</a> is " + info.ssllabs_grade + "."
        if info.ssllabs_grade == "F":
            good_connection.fail(grade_msg.format(info.domain))
            return
        msg += grade_msg
    else:
        msg += "(<a href=\"https://www.ssllabs.com/ssltest/analyze.html?d={}\" target=\"_blank\">SSL Labs report</a>)"
    info.secure_connection_works = True
    good_connection.succeed(msg.format(info.domain))


def check_https_page(info):
    info.can_load_https_page = False
    https_load = info.new_check()
    try:
        resp, tree = fetch_through_redirects("https://{}".format(info.domain))
        info.https_redirects_to_http = resp.url.startswith("http://")
        if info.https_redirects_to_http:
            https_load.fail("The HTTPS site redirects to HTTP.")
            return
        info.can_load_https_page = True
        good_sts = info.new_check()
        sts = resp.headers.get("Strict-Transport-Security")
        if sts is not None:
            m = re.search(r"max-age=(\d+)", sts)
            if m is not None:
                info.sts = int(m.group(1))
                if info.sts >= 2592000:
                    good_sts.succeed("<code>Strict-Transport-Security</code> header is set with a long <code>max-age</code> directive.")
                else:
                    good_sts.fail("<code>Strict-Transport-Security</code> header is set but the <code>max-age</code> is less than 30 days.")
            else:
                good_sts.fail("<code>Strict-Transport-Security</code> header doesn&rsquo;t contain a <code>max-age</code> directive.")
        else:
            good_sts.fail("<code>Strict-Transport-Security</code> header is not set.")
        info.mixed_content = tree is not None and has_mixed_content(tree)
        if info.mixed_content:
            https_load.fail("The HTML page loaded over HTTPS has mixed content.")
            return
    except requests.Timeout:
        https_load.fail("Requesting HTTPS page times out.")
        return
    except Not200 as e:
        https_load.fail("The HTTPS site returns an error status ({}) on request.".format(e.status))
        return
    except requests.ConnectionError:
        https_load.fail("Connection error when connecting to the HTTPS site.")
        return
    https_load.succeed("A page can be successfully fetched over HTTPS.")


def check_http_page(info):
    http_redirect = info.new_check()
    try:
        resp, tree = fetch_through_redirects("http://{}".format(info.domain))
        info.http_redirects_to_https = resp.url.startswith("https://")
        if info.http_redirects_to_https:
            http_redirect.succeed("HTTP site redirects to HTTPS.")
        else:
            http_redirect.fail("HTTP site doesn&rsquo;t redirect to HTTPS.")
    except requests.Timeout:
        http_redirect.fail("The HTTP site times out.")
        return
    except requests.ConnectionError:
        http_redirect.fail("Nothing is listening on port 80")
        return
    except Not200 as e:
        http_redirect.fail("The HTTP site returns an error status ({}) on request.".format(e.status))
        return


def check_site(site):
    log.info("Checking {}".format(site["domain"]))
    info = SiteInfo()
    info.domain = site["domain"]
    info.ssllabs_grade = site.get("ssllabs_grade")

    try:
        check_secure_connection(info)
        if not info.secure_connection_works:
            log.info("Couldn't connect securely to %s, so aborting further checks.", info.domain)
            return info

        check_https_page(info)
        if not info.can_load_https_page:
            log.info("Couldn't load HTTPS page for %s, so aborting further checks.", info.domain)
            return info

        check_http_page(info)
    except Exception:
        log.exception("unexpected failure evaluating %s", info.domain)
        raise

    return info


def set_site_template_data_from_info(site, info):
    site["checks"] = info.checks

    if (not info.secure_connection_works or
        not info.can_load_https_page or
            info.https_redirects_to_http or
            info.mixed_content):
        status = "bad"
    elif (not info.http_redirects_to_https or
          info.sts is None or info.sts < 2592000):
        status = "mediocre"
    else:
        status = "good"
    site["status"] = status


def regenerate_everything(ssllabs_grades_file):
    with open("config/meta.json", "r", encoding="utf-8") as fp:
        meta = json.load(fp)
    ssllabs_grades = {}
    if ssllabs_grades_file is not None:
        with open(ssllabs_grades_file, "r", encoding="utf-8") as fp:
            ssllabs_grades = json.load(fp)
    futures = []
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=PARALLELISM)
    for listing in meta["listings"]:
        if "external" in listing:
            continue
        with open("config/{}.json".format(listing["shortname"]), encoding="utf-8") as fp:
            listing["data"] = json.load(fp)
        for cat in listing["data"]["categories"]:
            for site in cat["sites"]:
                domain = site["domain"]
                if domain in ssllabs_grades:
                    site["ssllabs_grade"] = ssllabs_grades[domain]
                futures.append(executor.submit(check_site, site))
    with executor:
        while True:
            done, not_done = concurrent.futures.wait(futures, timeout=1)
            print("{}/{}".format(len(done), len(done) + len(not_done)))
            if not not_done:
                break
        infos = {}
        for f in futures:
            info = f.result()
            infos[info.domain] = info

    for listing in meta["listings"]:
        if "external" in listing:
            continue
        for cat in listing["data"]["categories"]:
            cat_status = collections.Counter()
            for site in cat["sites"]:
                info = infos[site["domain"]]
                set_site_template_data_from_info(site, info)
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
    parser.add_argument("--ssllabs")

    args = parser.parse_args()

    if args.cached:
        with open("cache.json", "r", encoding="utf-8") as fp:
            meta = json.load(fp)
    else:
        meta = regenerate_everything(args.ssllabs)
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
