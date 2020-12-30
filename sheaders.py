#!/usr/bin/env python3

# sheaders.py - Another security headers check!
# Copyleft 1977 - 2020 n00b
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import urllib.request, urllib.error, urllib.parse
import socket
import sys
import ssl
import os
import json
from optparse import OptionParser


class bcolors:
    HEADER = '\033[95m'
    UREDUJE = '\033[94m'
    UDUREJE = '\033[92m'
    PAZI = '\033[93m'
    PAO = '\033[91m'
    KRAJC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


# klijent zaglavlja koja se salju na definirani server u procesu http/s zahtjeva.
client_headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:53.0)\
 Gecko/20100101 Firefox/53.0',
    'Accept': 'text/html,application/xhtml+xml,\
 application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US;q=0.8,en;q=0.3',
    'Upgrade-Insecure-Requests': 1
 }


# Siguronosna zaglavlja koja bi trebala biti konfigurirana na definiranom serveru.
sec_headers = {
    'X-XSS-Protection': 'warning',
    'X-Frame-Options': 'warning',
    'X-Content-Type-Options': 'warning',
    'Strict-Transport-Security': 'error',
    'Public-Key-Pins': 'none',
    'Content-Security-Policy': 'warning',
    'X-Permitted-Cross-Domain-Policies': 'warning',
    'Referrer-Policy': 'warning'

}

information_headers = {
    'X-Powered-By',
    'Server'
}

cache_headers = {
    'Cache-Control',
    'Pragma',
    'Last-Modified'
    'Expires',
    'ETag'
}

headers = {}
json_headers = {}

def banner():
    print()
    print("=======================================================")
    print(" > sheaders.py - by n00b ..........................")
    print("-------------------------------------------------------")
    print(" Alat za provjeru sigurosnosnih zaglavlja na web serveru")
    print("=======================================================")
    print()


def colorize(string, alert):
    color = {
        'error':    bcolors.PAO + string + bcolors.KRAJC,
        'warning':  bcolors.PAZI + string + bcolors.KRAJC,
        'ok':       bcolors.UDUREJE + string + bcolors.KRAJC,
        'info':     bcolors.UREDUJE + string + bcolors.KRAJC
    }
    return color[alert] if alert in color else string


def parse_headers(hdrs):
    global headers
    headers = dict((x,y) for x,y in hdrs)

def append_port(target, port):
    return target[:-1] + ':' + port + '/' \
        if target[-1:] == '/' \
        else target + ':' + port + '/'


def set_proxy(proxy):
    if proxy is None:
        return
    proxyhnd = urllib.request.ProxyHandler({
        'http':  proxy,
        'https': proxy
    })
    opener = urllib.request.build_opener(proxyhnd)
    urllib.request.install_opener(opener)

def get_unsafe_context():
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def normalize(target):
    try:
        if (socket.inet_aton(target)):
            target = 'http://' + target
    except (ValueError, socket.error):
        pass
    finally:
        return target


def print_error(e):
    sys.stdout = sys.__stdout__
    if isinstance(e, ValueError):
        print("Nepoznata vrsta URL-a Unikatnog Resurs Povezioca")

    if isinstance(e, urllib.error.HTTPError):
            print("[!] URL Je vratio jednu HTTP gresku: {}".format(
                colorize(str(e.code), 'error')))

    if isinstance(e, urllib.error.URLError):
            if "CERTIFICATE_VERIFY_FAILED" in str(e.reason):
                print("SSL: Certificate validation error.\nIf you want to \
    ignore it run the program with the \"-d\" option.")
            else:
                print("Specificirani server koji provjeravate je izgleda nedostupan ({})".format(e.reason))


def check_target(target, options):
    '''
	Samo protokol za provjeru validnosti Internet Protokol adrese i provjera dal konekcija ka definiranom serveru funkcionira.
    vraca HEAD odgovore
    '''
    # recikliramo koristene opcije
    ssldisabled = options.ssldisabled
    useget = options.useget
    proxy = options.proxy
    response = None

    target = normalize(target)

    try:
        request = urllib.request.Request(target, headers=client_headers)

        # Set method
        method = 'GET' if useget else 'HEAD'
        request.get_method = lambda: method

        # Set proxy
        set_proxy(proxy)
        # Set certificate validation 
        if ssldisabled:
            context = get_unsafe_context()
            response = urllib.request.urlopen(request, timeout=10, context=context)
        else:
            response = urllib.request.urlopen(request, timeout=10)

    except Exception as e:
        print_error(e)
        sys.exit(1)

    if response is not None:
        return response
    print("Nemrem procitati odgovor sa definiranog servera.")
    sys.exit(3)


def is_https(target):
    '''
    Provjera dal' definirani server ima implementiran support za HTTPS kako bi Strict-Transport-Security funkcionirao
    '''
    return target.startswith('https://')


def report(target, safe, unsafe):
    print("-------------------------------------------------------")
    print("[!] Headers analizirani za {}".format(colorize(target, 'info')))
    print("[+] Pronadjeno {} siguronosnih zaglavlja".format(colorize(str(safe), 'ok')))
    print("[-] Nedostaje {} siguronosnih zaglavlja".format(
        colorize(str(unsafe), 'error')))
    print()

def main(options, targets):
    
    # dobavljam opcije
    port = options.port
    cookie = options.cookie
    custom_headers = options.custom_headers
    information = options.information
    cache_control = options.cache_control
    hfile = options.hfile
    json_output = options.json_output
    
    # ugasi printanje u terminal console output, ako je trazen da output bude u json fileu
    if json_output:
        global json_headers
        sys.stdout = open(os.devnull, 'w')

    banner()
    # Podesi baska port ako je setovan
    if cookie is not None:
        client_headers.update({'Cookie': cookie})
    
    # Podesi baska zaglavlje ukoliko je setovano
    if custom_headers is not None:
        for header in custom_headers:
            # Podijeli skupljene rijeci u formatu 'Header: value'
            header_split = header.split(': ')
            # Dodaj u postojecea zaglavlja koristeci ime zaglavlja i njegovu vrijednost Header: value
            try:
                client_headers.update({header_split[0]: header_split[1]})
            except IndexError:
                print("[!] Header strings must be of the format 'Header: value'")
                raise SystemExit(1)
    
    if hfile is not None:
        with open(hfile) as f:
            targets = f.read().splitlines()
        


    for target in targets:
        if port is not None:
            target = append_port(target, port)
        
        safe = 0
        unsafe = 0

        # Provjeri dal' je definirani server validan
        response = check_target(target, options)
        rUrl = response.geturl()

        print("[*] Analyzing headers of {}".format(colorize(target, 'info')))
        print("[*] Effective URL: {}".format(colorize(rUrl, 'info')))
        parse_headers(response.getheaders())
        json_headers["present"] = {}
        json_headers["missing"] = []

        for safeh in sec_headers:
            if safeh in headers:
                safe += 1
                json_headers["present"][safeh] = headers.get(safeh)

                # Ovdje beremo brigu o specijalnim zaglavljima koja bi mogla imati lose vrijednosti

                # X-XSS-Protection bi trebao bit ukljucen naravno.
                if safeh == 'X-XSS-Protection' and headers.get(safeh) == '0':
                    print("[*] Header {} in place! (Value: {})".format(
                            colorize(safeh, 'ok'),
                            colorize(headers.get(safeh), 'warning')))

                # Isprintaj poruku u terminal/console
                else:
                    print("[*] Header {} in place! (Value: {})".format(
                            colorize(safeh, 'ok'),
                            headers.get(safeh)))
            else:
                unsafe += 1
                json_headers["missing"].append(safeh)
                # HSTS radi samo na HTTPS
                if safeh == 'Strict-Transport-Security' and not is_https(rUrl):
                    unsafe -= 1
                    json_headers["missing"].remove(safeh)
                    continue
                print('[!] Nedostaje siguronosno zaglavlje: {}'.format(
                    colorize(safeh, sec_headers.get(safeh))))

        if information:
            json_headers["information_disclosure"] = {}
            i_chk = False
            print()
            for infoh in information_headers:
                if infoh in headers:
                    json_headers["information_disclosure"][infoh] = headers.get(ifoh)
                    i_chk = True
                    print("[!] Possible information disclosure: \
header {} in place! (Value: {})".format(
                            colorize(infoh, 'warning'),
                            headers.get(infoh)))
            if not i_chk:
                print("[*] No information disclosure headers detected")

        if cache_control:
            json_headers["caching"] = {}
            c_chk = False
            print()
            for cacheh in cache_headers:
                if cacheh in headers:
                    json_headers["caching"][cacheh] = headers.get(cacheh)
                    c_chk = True
                    print("[!] Cache control header {} in place! \
Value: {})".format(
                            colorize(cacheh, 'info'),
                            headers.get(cacheh)))
            if not c_chk:
                print("[*] No caching headers detected")

        report(rUrl, safe, unsafe)
        if json_output:
            sys.stdout = sys.__stdout__
            json_output = json.loads(str(json_headers).replace("\'", "\""))
            print(json.dumps(json_output))

if __name__ == "__main__":

    parser = OptionParser("Usage: %prog [options] <target>", prog=sys.argv[0])

    parser.add_option("-p", "--port", dest="port",
                      help="Set a custom port to connect to",
                      metavar="PORT")
    parser.add_option("-c", "--cookie", dest="cookie",
                      help="Set cookies for the request",
                      metavar="COOKIE_STRING")
    parser.add_option("-a", "--add-header", dest="custom_headers",
                      help="Add headers for the request e.g. 'Header: value'",
                      metavar="HEADER_STRING",
                      action="append")
    parser.add_option('-d', "--disable-ssl-check", dest="ssldisabled",
                      default=False,
                      help="Disable SSL/TLS certificate validation",
                      action="store_true")
    parser.add_option('-g', "--use-get-method", dest="useget",
                      default=False, help="Use GET method instead HEAD method",
                      action="store_true")
    parser.add_option("-j", "--json-output", dest="json_output",
                      default=False, help="Print the output in JSON format",
                      action="store_true")
    parser.add_option("-i", "--information", dest="information", default=False,
                      help="Display information headers",
                      action="store_true")
    parser.add_option("-x", "--caching", dest="cache_control", default=False,
                      help="Display caching headers",
                      action="store_true")
    parser.add_option("--proxy", dest="proxy",
                      help="Set a proxy (Ex: http://127.0.0.1:8080)",
                      metavar="PROXY_URL")
    parser.add_option("--hfile", dest="hfile",
                      help="Load a list of hosts from a flat file",
                      metavar="PATH_TO_FILE")
    (options, args) = parser.parse_args()

    if len(args) < 1 and options.hfile is None :
        parser.print_help()
        sys.exit(1)
    main(options, args)
