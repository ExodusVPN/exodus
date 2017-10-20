#!/usr/bin/env python3
# coding: utf8

import os, sys, time
import signal, logging, json

import urllib.parse
import urllib.request


logger = logging.getLogger('parse')

registries = ("arin", "ripencc", "apnic", "lacnic", "afrinic", "iana")
datadir    = os.path.join(os.getcwd(), "data")

"""
RIR statistics exchange format:
    ftp://ftp.apnic.net/public/stats/afrinic/README-EXTENDED.txt
    https://www.apnic.net/about-apnic/corporate-documents/documents/resource-guidelines/rir-statistics-exchange-format/#FileExchange

The resources reported are:
    - IPv4 address ranges (IPv4)
    - IPv6 address ranges (IPv6)
    - Autonomous System Numbers (ASNs)    
"""

# ISO-3166-1993
COUNTRY_CODES = (
    'AD', 'AE', 'AF', 'AG', 'AI', 'AL', 'AM', 'AO', 'AR', 'AS', 'AT', 'AU', 'AW', 'AX', 'AZ', 
    'BA', 'BB', 'BD', 'BE', 'BF', 'BG', 'BH', 'BI', 'BJ', 'BL', 'BM', 'BN', 'BO', 'BQ', 'BR', 
    'BS', 'BT', 'BW', 'BY', 'BZ', 'CA', 'CD', 'CF', 'CG', 'CH', 'CI', 'CK', 'CL', 'CM', 'CN', 
    'CO', 'CR', 'CU', 'CV', 'CW', 'CY', 'CZ', 'DE', 'DJ', 'DK', 'DM', 'DO', 'DZ', 'EC', 'EE', 
    'EG', 'ER', 'ES', 'ET', 'EU', 'FI', 'FJ', 'FM', 'FO', 'FR', 'GA', 'GB', 'GD', 'GE', 'GF', 
    'GG', 'GH', 'GI', 'GL', 'GM', 'GN', 'GP', 'GQ', 'GR', 'GT', 'GU', 'GW', 'GY', 'HK', 'HN', 
    'HR', 'HT', 'HU', 'ID', 'IE', 'IL', 'IM', 'IN', 'IO', 'IQ', 'IR', 'IS', 'IT', 'JE', 'JM', 
    'JO', 'JP', 'KE', 'KG', 'KH', 'KI', 'KM', 'KN', 'KP', 'KR', 'KW', 'KY', 'KZ', 'LA', 'LB', 
    'LC', 'LI', 'LK', 'LR', 'LS', 'LT', 'LU', 'LV', 'LY', 'MA', 'MC', 'MD', 'ME', 'MF', 'MG', 
    'MH', 'MK', 'ML', 'MM', 'MN', 'MO', 'MP', 'MQ', 'MR', 'MS', 'MT', 'MU', 'MV', 'MW', 'MX', 
    'MY', 'MZ', 'NA', 'NC', 'NE', 'NF', 'NG', 'NI', 'NL', 'NO', 'NP', 'NR', 'NU', 'NZ', 'OM', 
    'PA', 'PE', 'PF', 'PG', 'PH', 'PK', 'PL', 'PM', 'PR', 'PS', 'PT', 'PW', 'PY', 'QA', 'RE', 
    'RO', 'RS', 'RU', 'RW', 'SA', 'SB', 'SC', 'SD', 'SE', 'SG', 'SI', 'SK', 'SL', 'SM', 'SN', 
    'SO', 'SR', 'SS', 'ST', 'SV', 'SX', 'SY', 'SZ', 'TC', 'TD', 'TG', 'TH', 'TJ', 'TK', 'TL', 
    'TM', 'TN', 'TO', 'TR', 'TT', 'TV', 'TW', 'TZ', 'UA', 'UG', 'US', 'UY', 'UZ', 'VA', 'VC', 
    'VE', 'VG', 'VI', 'VN', 'VU', 'WF', 'WS', 'YE', 'YT', 'ZA', 'ZM', 'ZW', 'ZZ'
)

class RIR(object):
    def __init__(self, filename, header, records):
        assert(type(filename) == str)
        assert(isinstance(header, RIRHeader))
        assert(type(records) == list)
        for x in records:
            assert(isinstance(x, RIRRecord))

        self.filename = filename
        self.header   = header
        self.records  = records

    @classmethod
    def from_string(cls, content, filename="unknow"):
        return cls.parse(content, filename=filename)

    @classmethod
    def from_url(cls, url):
        content = urllib.request.urlopen(url).read().decode("UTF-8")
        filename = os.path.split(url)[-1]
        return cls.parse(content, filename=filename)

    @classmethod
    def from_filepath(cls, filepath):
        content = open(filepath, "rb").read().decode("UTF-8")
        filename = os.path.split(filepath)[-1]
        return cls.parse(content, filename=filename)

    @staticmethod
    def _parse_version_line(line):
        # 2    |iana       |20171005 |2804  |19830101  |20170722 |+0000
        version, registry, serial, records, startdate, enddate, utc_offset = line.split("|")
        version = float(version)
        assert(version in (2.0, 2.3))
        assert(registry in registries)
        records = int(records)
        
        if not utc_offset.startswith("+"):
            utc_offset = "+" + utc_offset

        return (version, registry, serial, records, startdate, enddate, utc_offset)

    @staticmethod
    def _parse_summary_line(line):
        # iana|*|ipv6|*|57|summary
        registry, _, _type, _, count, summary = line.split("|")
        assert(registry in registries)
        assert(_type in ("asn", "ipv4", "ipv6"))
        assert(summary == 'summary')
        count = int(count)

        return (registry, _type, count, summary)
        

    @staticmethod
    def _parse_record_line(line):
        # iana|ZZ|asn|28|1|19920101|ripencc
        # iana|ZZ|ipv4|174.0.0.0|16777216|20080215|arin
        # iana|ZZ|ipv6|2001:3000::|21|20040501|ripencc
        # apnic|JP|asn|2554|1|20020801|allocated
        # apnic|MY|ipv4|27.0.4.0|1024|20100310|allocated
        fields = line.split("|")
        assert(len(fields) >= 7)

        registry, cc, _type, start, value, date, status = fields[:7]
        extensions = tuple(fields[7:])

        if cc.strip() == "":
            cc = "ZZ"

        assert(cc in COUNTRY_CODES)
        assert(registry in registries)
        assert(_type in ("asn", "ipv4", "ipv6"))
        
        status_set = (
            "allocated", "assigned", "available", "reserved", 
            "arin", "ripencc", "apnic", "lacnic", "afrinic", "iana", "ietf"
        )
        assert(status in status_set)
        
        if _type == "asn":
            start = int(start)
        if _type == "ipv4":
            pass
        if _type == "ipv6":
            pass
        
        value = int(value)

        return (registry, cc, _type, start, value, date, status, extensions)

    @classmethod
    def parse(cls, content, filename="unknow"):
        lines = list(filter(lambda line: not line.startswith("#"), content.split("\n")))
        assert(len(lines) >= 2)

        header    = cls._parse_version_line(lines[0].strip())
        summaries = []
        records   = []

        lines = lines[1:]
        for line in lines:
            line = line.strip()
            if line and len(line) > 0:
                if line.endswith("summary"):
                    summaries.append(cls._parse_summary_line(line))
                else:
                    records.append(cls._parse_record_line(line))

        return (header, summaries, records)

def parse():
    names = list(map(lambda registry: "delegated-{}-extended-latest".format(registry), registries))
    names += list(map(lambda registry: "delegated-{}-latest".format(registry), registries))
    filenames = list(filter(lambda filename: filename in names, os.listdir(datadir)))
    
    country_codes = set()

    records = []
    for filename in filenames:
        logger.info("parse %s/%s", datadir, filename)
        _, _, _records = RIR.from_filepath(os.path.join(datadir, filename))
        records.extend(_records)

    # ('ripencc', 'ZZ', 'ipv6', '2a0d:d080::', 25, '', 'available', ())
    print(len(records)) # length: 665570 mem: ~= 290 MB
    open("data/records.json", "wb").write(json.dumps(records).encode("UTF-8"))
    open("data/country_codes.json", "wb").write(json.dumps(COUNTRY_CODES).encode("UTF-8"))


def main():
    if not os.path.exists(datadir):
        os.makedirs(datadir)
    
    parse()


if __name__ == '__main__':
    logging.basicConfig(
        format  = 'PID %(process)d %(asctime)s \x1b[32m%(levelname)-7s\x1b[0m %(threadName)-14s %(name)-15s %(message)s',
        datefmt = '%Y-%m-%d %H:%M:%S',
        level   = logging.DEBUG
    )
    
    logging.getLogger("chardet.charsetprober").setLevel(logging.CRITICAL)
    logging.getLogger("chardet.universaldetector").setLevel(logging.CRITICAL)

    signal.signal(signal.SIGINT,  signal.SIG_DFL)
    signal.signal(signal.SIGSEGV, signal.SIG_DFL)
    signal.signal(signal.SIGCHLD, signal.SIG_IGN)

    main()