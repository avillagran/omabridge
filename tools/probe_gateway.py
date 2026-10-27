#!/usr/bin/env python3
"""Bounded, unauthenticated HTTPS latency/encoding probe for a T3 gateway.

Measures complete requests with fresh client connections, not WebSocket latency.
Never reads credentials or disables TLS verification. No response bodies are printed.
"""
import argparse
import json
import math
import statistics
import time
import urllib.parse
import urllib.request
import zlib

LIMIT = 64 * 1024


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', required=True, help='HTTPS origin, without credentials or a path')
    parser.add_argument('--environment-id', required=True, help='Expected ID from the host local descriptor')
    parser.add_argument('--samples', type=int, default=5)
    args = parser.parse_args()
    url = urllib.parse.urlsplit(args.url)
    if url.scheme != 'https' or not url.hostname or url.username or url.password or url.query or url.fragment or url.path not in ('', '/'):
        parser.error('use an HTTPS origin without credentials, query, fragment or path')
    if not 1 <= args.samples <= 20:
        parser.error('samples must be between 1 and 20')
    origin = urllib.parse.urlunsplit((url.scheme, url.netloc, '', '', ''))
    opener = urllib.request.build_opener(NoRedirects())
    durations, sizes, encodings = [], [], set()
    for _ in range(args.samples):
        request = urllib.request.Request(origin + '/.well-known/t3/environment', headers={'Accept-Encoding': 'gzip', 'Connection': 'close'})
        started = time.perf_counter()
        with opener.open(request, timeout=8) as response:
            if response.status != 200 or response.headers.get_content_type() != 'application/json':
                raise ValueError('expected a JSON T3 descriptor')
            raw = response.read(LIMIT + 1)
            encoding = response.headers.get('Content-Encoding', 'identity').lower()
        durations.append((time.perf_counter() - started) * 1000)
        if len(raw) > LIMIT:
            raise ValueError('descriptor exceeds response limit')
        sizes.append(len(raw)); encodings.add(encoding)
        if encoding == 'gzip':
            decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
            decoded = decoder.decompress(raw, LIMIT + 1)
            if len(decoded) > LIMIT or not decoder.eof or decoder.unused_data:
                raise ValueError('invalid or oversized gzip descriptor')
        elif encoding == 'identity':
            decoded = raw
        else:
            raise ValueError('unexpected content encoding')
        if json.loads(decoded).get('environmentId') != args.environment_id:
            raise ValueError('gateway reached a different T3 environment')
    ordered = sorted(durations)
    print(json.dumps({'origin': origin, 'environmentVerified': True, 'samples': len(durations),
        'measurement': 'complete HTTPS descriptor requests; fresh client connections',
        'latencyMs': {'p50': round(statistics.median(durations), 1), 'p95': round(ordered[math.ceil(.95 * len(ordered)) - 1], 1)},
        'meanResponseBytes': round(statistics.mean(sizes), 1), 'contentEncodings': sorted(encodings)}, indent=2))


if __name__ == '__main__':
    main()
