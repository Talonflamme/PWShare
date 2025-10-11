import re
import socket
import ssl
import subprocess
import sys
import time

import click


def set_cipher(ctx: ssl.SSLContext, cipher: str):
    try:
        ctx.set_ciphers(cipher)
        return
    except ssl.SSLError:
        pass

    output = subprocess.check_output("openssl ciphers -v -V").decode("utf-8")
    for byte1, byte2, name in re.findall(r"0x([A-z0-9]{2}),0x([A-z0-9]{2})\s-\s([A-z0-9_-]+)", output):
        code = (f""
                f"{byte1}{byte2}").lower()
        if code == cipher.lower():
            ctx.set_ciphers(name)
            break
    else:
        print("Could not set cipher:", cipher, file=sys.stderr)
        exit(1)


@click.command()
@click.option("-h", "--host", type=str, default="localhost", help="Server hostname", show_default=True)
@click.option("-p", "--port", type=int, help="Port number", default=4981, show_default=True)
@click.option("-c", "--cipher", type=str,
              help="Cipher. Either use the OpenSSL name or a 2-byte code value (with 0 padding). E.g: '0035'",
              required=True)
@click.option("-e", "--expect", type=str, help="What text to expect to receive from the server",
              default="Hello World!", show_default=True)
@click.option("-s", "--send", type=str, help="What to send to the server", default=None, show_default=True)
@click.option("-d", "--delay", type=int, help="Delay in ms to wait before connecting", default=0, show_default=True)
def cli(host: str, port: int, cipher: str, expect: str, send: str | None, delay: int):
    context = ssl.create_default_context()

    set_cipher(context, cipher)

    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    expect = expect.encode("utf-8")

    if delay > 0:
        time.sleep(delay / 1000)

    with socket.create_connection((host, port)) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            recv = ssock.recv(1024)

            if recv != expect:
                print(f"Expected: {expect!r}, got: {recv!r}", file=sys.stderr)
                exit(1)

            if send is not None:
                ssock.sendall(send.encode("utf-8"))


if __name__ == '__main__':
    cli()
