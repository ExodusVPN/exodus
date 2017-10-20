#!/usr/bin/env python3
# coding: utf8

import os, sys, time
import signal, logging, json

import urllib.parse
import urllib.request


# IANA Numbers
#   https://www.iana.org/numbers

# ARIN     (Canada, United States, some Caribbean nations)
# RIPE NCC (Europe, Russia, Middle East, Central Asia)
# APNIC    (Asia-Pacific region)
# LACNIC   (Latin America, some Caribbean nations)
# AFRINIC  (Africa) 
# IANA

# ARIN
# ftp://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest
# RIPE NCC
# ftp://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-latest
# APNIC
# ftp://ftp.apnic.net/public/stats/apnic/delegated-apnic-latest
# LACNIC
# http://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-latest
# AFRINIC
# ftp://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-latest

# IANA
# ftp://ftp.apnic.net/public/stats/iana/delegated-iana-latest
# https://www.iana.org/assignments/ipv4-address-space/ipv4-address-space.xhtml
# https://www.iana.org/assignments/ipv6-address-space/ipv6-address-space.xhtml
# https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
# https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml

# <registry>/delegated-<registry>-latest
# <registry>/delegated-<registry>-latest.md5
# <registry>/delegated-<registry>-extended-latest
# <registry>/delegated-<registry>-extended-latest.md5

# rsync www.apnic.net::stats/<registry>/delegated-<registry>-latest


# Autonomous System Numbers
#   https://www.iana.org/assignments/as-numbers/as-numbers.xml
# 16-bit: 00000-0000065535
# 32-bit: 65536-4294967295

logger = logging.getLogger('sync')

registries = (
    ("arin",    "ftp://ftp.arin.net/pub/stats"), 
    ("ripencc", "ftp://ftp.ripe.net/pub/stats"),
    ("apnic",   "ftp://ftp.apnic.net/public/stats"),
    ("lacnic",  "http://ftp.lacnic.net/pub/stats"),
    ("afrinic", "ftp://ftp.afrinic.net/pub/stats"),
    ("iana",    "ftp://ftp.apnic.net/public/stats")
)

filenames = ( "delegated-{}-latest", "delegated-{}-extended-latest" )

datadir = os.path.join(os.getcwd(), "data")


def save(filepath, content):
    if not os.path.exists(datadir):
        os.makedirs(datadir)
    open(filepath, "wb").write(content.encode("UTF-8"))


def sync(registry):
    url_base = registry[1]
    registry_name = registry[0]
    for filename in list(map(lambda s: s.format(registry_name), filenames)):
        filepath  = os.path.join(datadir, filename)
        url = "{}/{}/{}".format(url_base, registry_name, filename)
        
        md5_fileurl  = "{}.md5".format(url)
        md5_filepath = "{}.md5".format(filepath)

        is_new = False
        md5_http_content = None
        try:
            logger.info("GET %s ...", md5_fileurl)
            md5_http_content = urllib.request.urlopen(md5_fileurl).read().decode("UTF-8")
        except (urllib.error.HTTPError, urllib.error.URLError) as e:
            if url == "ftp://ftp.apnic.net/public/stats/iana/delegated-iana-latest":
                is_new = True
            else:
                white_list = (
                    "ftp://ftp.arin.net/pub/stats/arin/delegated-arin-latest.md5",
                    "ftp://ftp.arin.net/pub/stats/arin/delegated-arin-latest",
                    "ftp://ftp.apnic.net/public/stats/iana/delegated-iana-latest.md5",
                    "ftp://ftp.apnic.net/public/stats/iana/delegated-iana-latest",
                    "ftp://ftp.apnic.net/public/stats/iana/delegated-iana-extended-latest.md5",
                    "ftp://ftp.apnic.net/public/stats/iana/delegated-iana-extended-latest"
                )
                if url not in white_list:
                    logger.warn("GET %s %s", md5_fileurl, e.reason)
                continue
        except Exception as e:
            logger.exception(e)

        if os.path.exists(md5_filepath) and os.path.isfile(md5_filepath):
            md5_file_content = open(md5_filepath, "rb").read().decode("UTF-8")
            if md5_http_content and (md5_http_content != md5_file_content):
                is_new = True
        else:
            is_new = True

        if not is_new:
            continue

        try:
            logger.info("GET %s ...", url)
            res = urllib.request.urlopen(url).read().decode("UTF-8")
            save(filepath, res)
            if md5_http_content:
                save(md5_filepath, md5_http_content)
        except (urllib.error.HTTPError, urllib.error.URLError) as e:
            logger.warn("GET %s %s", url, e.reason)
        except Exception as e:
            logger.exception(e)

def main():
    logger.warn("提示： 如果你在中国内地，请确保你连上了全局代理或者VPN，否则可能会出现一些文件无法下载的问题！")
    
    for registry in registries:
        sync(registry)

    sync_date = time.strftime("%Y%m%d")
    logger.info("Last sync date: %s", sync_date)
    
    open("last_sync_date", "wb").write(sync_date.encode("UTF-8"))

if __name__ == '__main__':
    logging.basicConfig(
        format  = 'PID %(process)d %(asctime)s \x1b[32m%(levelname)-7s\x1b[0m %(threadName)-14s %(name)-15s %(message)s',
        datefmt = '%Y-%m-%d %H:%M:%S',
        level   = logging.DEBUG
    )

    signal.signal(signal.SIGINT,  signal.SIG_DFL)
    signal.signal(signal.SIGSEGV, signal.SIG_DFL)
    signal.signal(signal.SIGCHLD, signal.SIG_IGN)

    main()
