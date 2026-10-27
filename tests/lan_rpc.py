#!/usr/bin/env python3
"""Single RPC to the disposable second-machine test endpoint over a private Unix socket."""
import argparse
import socket
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", required=True)
    args = parser.parse_args()
    request = sys.stdin.buffer.readline(8192)
    assert request, "missing lab request"
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(15)
        client.connect(args.socket)
        client.sendall(request)
        response = client.makefile("rb").readline(65536)
        assert response, "lab host closed control socket"
        sys.stdout.buffer.write(response)


if __name__ == "__main__":
    main()
