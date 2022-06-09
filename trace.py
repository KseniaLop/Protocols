import argparse
import re
import subprocess
import json
import requests


def get_info(ip):
    mes = ""
    info = json.loads(requests.get(f"http://ipinfo.io/{ip}/json").content)
    if 'asn' in info:
        mes = f", ASN: {info['asn']}"
    if 'country' in info:
        mes = f", Country: {info['country']}"
    if 'city' in info:
        mes = f", City: {info['city']}"
    return mes


def decode_str(line):
    decoded_line = line.decode('CP866')
    local_ip = re.findall(r"192\.168\.\d{1,3}\.\d{1,3}", decoded_line)
    ip = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", decoded_line)
    miss = re.findall(r"\* {8}\* {8}\*", decoded_line)
    if local_ip:
        return f"IP: {ip[0]}, ASN: Local"
    elif ip:
        return f"IP: {ip[0]}{get_info(ip[0])}"
    elif miss:
        return f"****"


def trace(address):
    result = []
    routs = subprocess.check_output(["tracert", address]).splitlines()
    for line in routs:
        dec_line = decode_str(line)
        if dec_line is not None:
            result.append(dec_line)
    result = result[1:]
    return result


def main():
    parser = argparse.ArgumentParser(description='Route trace')
    parser.add_argument('address', help='IP or domain name')
    args = parser.parse_args()
    j = 1
    for line in trace(args.address):
        print(str(j) + ' ' + line)
        j += 1


if __name__ == "__main__":
    main()