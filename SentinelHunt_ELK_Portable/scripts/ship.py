#!/usr/bin/env python3
"""Small local endpoint shipper / continuous TCP file forwarder."""
import argparse
import hashlib
import json
import socket
import sys
import time
from pathlib import Path
from manage import push, validate_feed

def envelope(line, source, identity, feed_name=None):
    return {'record_id': 'ship-'+hashlib.sha256(((feed_name or source)+'\n'+source+'\n'+identity+'\n'+line).encode()).hexdigest(),
            'source_name': source, 'feed_name': validate_feed(feed_name or source), 'raw_line': line}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['push','stream'])
    parser.add_argument('path', type=Path)
    parser.add_argument('--source', default='local-endpoint')
    parser.add_argument('--feed', help='Stable feed name; defaults to --source for raw files')
    parser.add_argument('--follow', action='store_true', help='Keep consuming newly appended lines; Ctrl+C stops')
    parser.add_argument('--envelopes', action='store_true', help='Push pre-wrapped inputs.ndjson, preserving record/capture IDs')
    args = parser.parse_args()
    if args.feed is not None: validate_feed(args.feed)
    connection = socket.create_connection(('127.0.0.1',15514), timeout=15) if args.mode == 'stream' else None
    if connection: connection.settimeout(15)
    sent = 0
    try:
        with args.path.open() as source:
            while True:
                offset = source.tell()
                line = source.readline()
                if not line or not line.endswith('\n'):
                    source.seek(offset)
                    if args.follow:
                        time.sleep(0.5)
                        continue
                    if line: raise ValueError('Final record lacks newline; append newline and retry')
                    break
                line = line.rstrip('\n').rstrip('\r')
                if not line: continue
                row = json.loads(line) if args.envelopes else envelope(
                    line, args.source, str(args.path.resolve())+':'+str(offset), args.feed)
                if args.feed is not None: row['feed_name'] = args.feed
                allowed = {'record_id','capture_id','raw_line','source_name','feed_name'}
                if set(row)-allowed or not isinstance(row.get('raw_line'),str):
                    raise ValueError('Invalid raw input envelope')
                if row.get('feed_name') is not None: validate_feed(row['feed_name'])
                if args.mode == 'push':
                    push(row)
                else:
                    wrapped = dict(row, transport_envelope='sentinelhunt.raw.v1')
                    connection.sendall((json.dumps(wrapped)+'\n').encode())
                sent += 1
                print(f'Accepted by transport: {sent}', flush=True)
        print('Transport finished. Verify indexed records separately in raw staging.')
    finally:
        if connection: connection.close()

if __name__ == '__main__':
    try: main()
    except KeyboardInterrupt: print('\nForwarder stopped.')
    except Exception as error:
        print(f'STOP: {error}',file=sys.stderr);sys.exit(1)
