#!/usr/bin/env python3
# coding: utf8

import os, sys, time
import signal, logging, json


logger  = logging.getLogger('codegen')

datadir    = os.path.join(os.getcwd(), "data")
registries = ('afrinic', 'apnic', 'arin', 'iana', 'ietf', 'lacnic', 'ripencc')

COUNTRY_CODES = json.loads(open("data/country_codes.json", "rb").read().decode("UTF-8"))


"""
IANA

----------  ---------------------------------------------
Registry    Area Covered
----------  ---------------------------------------------
AFRINIC     Africa Region
APNIC       Asia/Pacific Region
ARIN        Canada, USA, and some Caribbean Islands
LACNIC      Latin America and some Caribbean Islands
RIPE NCC    Europe, the Middle East, and Central Asia
----------  ---------------------------------------------
"""

ipv4_prefixs = (0,
     1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16,
    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32
)

ipv6_prefixs = (0, 
      1,   2,  3,    4,   5,   6,   7,   8,   9,  10,  11,  12,  13,  14,  15,  16,
     17,  18,  19,  20,  21,  22,  23,  24,  25,  26,  27,  28,  29,  30,  31,  32, 
     33,  34,  35,  36,  37,  38,  39,  40,  41,  42,  43,  44,  45,  46,  47,  48, 
     49,  50,  51,  52,  53,  54,  55,  56,  57,  58,  59,  60,  61,  62,  63,  64, 
     65,  66,  67,  68,  69,  70,  71,  72,  73,  74,  75,  76,  77,  78,  79,  80, 
     81,  82,  83,  84,  85,  86,  87,  88,  89,  90,  91,  92,  93,  94,  95,  96, 
     97,  98,  99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112,
    113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128
)

def ipv4_to_u64(s):
    array = list(map(lambda sn: int(sn), s.split(".")))
    assert(len(array) == 4)
    for x in array:
        assert(x >= 0 and x <= 255)
    n =   ( (array[0] & 0xff) << 24) \
        + ( (array[1] & 0xff) << 16) \
        + ( (array[2] & 0xff) <<  8) \
        + ( (array[3] & 0xff) <<  0)
    return n

def ipv6_to_u128(s):
    # WARN: 暂不支持 连缀符号`.`
    assert("." not in s)
    s = s.replace("::", "...")
    assert(s.count("...") <= 1)
    if s.count(":") != 7 and "..." in s:
        if s.startswith("..."):
            s = s.replace("...", ":".join(list("0"*(7-s.count(":")))) + ":")
        elif s.endswith("..."):
            s = s.replace("...", ":" + ":".join(list("0"*(7-s.count(":")))))
        else:
            s = s.replace("...", ":" + ":".join(list("0"*(6-s.count(":")))) + ":")
    tmp = s.split(":")
    assert(len(tmp) == 8)
    bits = "".join(list(map(lambda sn: bin(int(sn, 16)).replace("0b", "").rjust(16, "0"), tmp)))
    assert(len(bits) == 128)
    array = []
    pos = 0
    while 1:
        _bits = bits[pos: pos+8]
        if len(_bits) != 8:
            break
        array.append(int(_bits, 2))
        pos += 8
    _bits = None
    pos = None
    assert(len(array) == 16)
    for x in array:
        assert(x >= 0 and x <= 255)
    n =   ( (array[ 0] & 0xff) << 120) \
        + ( (array[ 1] & 0xff) << 112) \
        + ( (array[ 2] & 0xff) << 104) \
        + ( (array[ 3] & 0xff) <<  96) \
        + ( (array[ 4] & 0xff) <<  88) \
        + ( (array[ 5] & 0xff) <<  80) \
        + ( (array[ 6] & 0xff) <<  72) \
        + ( (array[ 7] & 0xff) <<  64) \
        + ( (array[ 8] & 0xff) <<  56) \
        + ( (array[ 9] & 0xff) <<  48) \
        + ( (array[10] & 0xff) <<  40) \
        + ( (array[11] & 0xff) <<  32) \
        + ( (array[12] & 0xff) <<  24) \
        + ( (array[13] & 0xff) <<  16) \
        + ( (array[14] & 0xff) <<   8) \
        + ( (array[15] & 0xff) <<   0) 
    return n

def u64_to_ipv4(n):
    assert(n >= 0 and n <= 4294967295)
    array = (
        ((n >> 24) & 0xff),
        ((n >> 16) & 0xff), 
        ((n >>  8) & 0xff),
        ((n >>  0) & 0xff)
    )
    str_array = list(map(lambda n: str(n), array))
    return ".".join(str_array)

def u128_to_ipv6(n):
    assert(n >= 0 and n <= 340282366920938463463374607431768211455)
    bits = bin(n).replace("0b", "").rjust(128, "0")
    assert(len(bits) == 128)

    array = []
    pos = 0
    while 1:
        _bits = bits[pos: pos+16]
        if len(_bits) != 16:
            break
        array.append(hex(int(_bits, 2)).replace("0x", "").rjust(4, "0") )
        pos += 16
    _bits = None
    pos = None
    assert(len(array) == 8)

    return ":".join(array)


def ipv4_range_block(ipv4_addr, count=None, prefix=None):
    start = ipv4_to_u64(ipv4_addr)

    if type(count) == int:
        return (start, start+count)

    if type(prefix) == int and prefix in ipv4_prefixs:
        return (start, start+2**(32-prefix))

    raise ValueError('Ooops ...')


def ipv6_range_block(ipv6_addr, count=None, prefix=None):
    start = ipv6_to_u128(ipv6_addr)
    if type(count) == int:
        return (start, start+count)

    if type(prefix) == int and prefix in ipv6_prefixs:
        return (start, start+2**(128-prefix))

    raise ValueError('Ooops ...')

def ip_cidr(start_ip, end_ip):
    if "." in start_ip and "." in end_ip:
        # IPv4
        start_number = ipv4_to_u64(start_ip)
        end_number   = ipv4_to_u64(end_ip)
        if start_number == end_number:
            return "%s/%d" % (start_ip, 32)
        elif start_number < end_number:
            return "%s/%s" % (start_ip, 32-len(bin(end_number - start_number).replace("0b", "")))
        elif start_number > end_number:
            raise ValueError('Ooops ...')
        else:
            raise ValueError('Ooops ...')
    elif ":" in end_ip :
        # IPv6
        start_number = ipv6_to_u128(start_ip)
        end_number   = ipv6_to_u128(end_ip)
        if start_number == end_number:
            return "%s/%d" % (start_ip, 128)
        elif start_number < end_number:
            return "%s/%s" % (start_ip, 128-len(bin(end_number - start_number).replace("0b", "")))
        elif start_number > end_number:
            raise ValueError('Ooops ...')
        else:
            raise ValueError('Ooops ...')
    else:
        raise ValueError('Ooops ...')

def ip_classful(s):
    # https://en.wikipedia.org/wiki/Classful_network#Classful_addressing_definition
    if "." in s:
        # IPv4
        number = ipv4_to_u64(s)
        bits = bin(number).replace("0b", "").rjust(32, "0")
        if number >= 0b11110000000000000000000000000000 and number <= 0b11111111111111111111111111111111:
            # 240.0.0.0 - 255.255.255.255
            return "E"
        elif bits.startswith("1110"):
            # 224.0.0.0 - 239.255.255.255
            return "D"
        elif bits.startswith("110"):
            # 192.0.0.0 - 223.255.255.255
            return "C"
        elif bits.startswith("10"):
            # 128.0.0.0 - 191.255.255.255
            return "B"
        elif bits.startswith("0"):
            # 0.0.0.0 - 127.255.255.255
            return "A"
        else:
            raise ValueError('Ooops ...')
    else:
        # IPv6
        return "N/A"

def ip_subnet_mask(s):
    classful = ip_classful(s)
    if classful == 'A':
        return ipv4_to_u64("255.0.0.0")
    elif classful == 'B':
        return ipv4_to_u64("255.255.0.0")
    elif classful == 'C':
        return ipv4_to_u64("255.255.255.0")
    elif classful == 'D':
        raise ValueError("not defined")
    elif classful == 'E':
        raise ValueError("not defined")
    elif classful == 'N/A':
        # IPv6
        # a:b:c:d:e:f:g:h
        # Network address: 00 -  48 bits  (a, b, c)
        # Subnet address : 48 -  64 bits  (d, )
        # Device address : 64 - 128 bits  (e, f, g, h)
        return "ffff:ffff:ffff:ffff::"
    else:
        raise ValueError("Ooops ...")


def gen_asn_code():
    pass

def gen_ip_code():
    pass

def get_china_ipv4_list():
    records = json.loads(open("data/records.json", "rb").read().decode("UTF-8"))

    data   = []
    counts = {}

    total_ipv4_num = 0
    total_ipv6_num = 0

    for (registry, cc, _type, start, value, date, status, extensions) in records:
        # ('ripencc', 'ZZ', 'ipv6', '2a0d:d080::', 25, '', 'available', ())
        if cc == 'CN' and _type == 'ipv4':
            start_ipv4_u64 = ipv4_to_u64(start)
            if start_ipv4_u64 in data:
                if counts[start_ipv4_u64] != value:
                    raise ValueError("Ooops ...")
            else:
                data.append(start_ipv4_u64)
                counts[start_ipv4_u64] = value
                total_ipv4_num += value
        elif cc == 'CN' and _type == 'ipv6':
            # logger.info("%s  -- %d", start, value)
            _b, _e = ipv6_range_block(start, prefix=value)
            total_ipv6_num += _e - _b

    logger.info("total_ipv6_num: %d", total_ipv6_num) # 33 8019 0390 7905 6795 8280 9345 3126 8608
    logger.info("total_ipv4_num: %d", total_ipv4_num) # 339122432                          3.39 亿
    
    records = None
    data.sort()
    while 1:
        num = 0
        idx = 0
        while idx < len(data) - 1:
            if data[idx] + counts[data[idx]] == data[idx+1]:
                counts[data[idx]] += counts[data[idx+1]]
                data.remove(data[idx+1])
                num += 1
            idx += 1
        if num == 0:
            break


def codegen():
    pass


def test():
    # print(ip_cidr("0.0.0.1"))
    # print(ipv4_to_u64("0.0.0.0"))
    print(ip_cidr("61.5.208.0", "61.5.208.0"))
    print(ip_cidr("61.5.208.0", "61.5.223.255"))
    print(ip_cidr("103.43.155.0", "103.43.155.255"))

    print(ip_cidr("2001:268:2000::", "2001:268:3fff:ffff:ffff:ffff:ffff:ffff"))

    print(ip_classful("61.5.208.0"))
    print(ip_classful("103.43.157.100"))
    print(ip_classful("255.255.255.255"))

    return
    start, end = ipv4_range_block("103.43.156.0", prefix=26)
    print(end-start, u64_to_ipv4(start), u64_to_ipv4(end))
    # print(ipaddress.IPv4Network("103.43.156.0/22").num_addresses)

    start, end = ipv6_range_block("2001:268:2000::", prefix=35)
    print(end-start, u128_to_ipv6(start), u128_to_ipv6(end))
    # print(ipaddress.IPv6Network("2001:268:2000::/35").num_addresses)

    # return
    print(ipv6_to_u128( "2001:268:2000::" ))
    print(ipv6_to_u128( "2001:268:2000::2:3" ))
    print(ipv6_to_u128( "::2001:268:2000" ))

    # print(ipv6_to_u128( str(ipaddress.IPv6Address("2001:268:2000::").exploded) ))
    # print(ipaddress.IPv6Address(42540536976427471861665356247566647296).exploded)
    print(u128_to_ipv6(42540536976427471861665356247566647296))


def main():
    test()
    # get_china_ipv4_list()


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