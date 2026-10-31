"""Public CLI skeleton; implementation belongs in permitgate.gateway."""
import argparse
import json

from .canonical import parse_line
from .gateway import Gateway

def run(args):
    # The complete solution should verify, bind and persist trust identity on first boot.
    gateway = Gateway(args.trust, args.state)
    with open(args.input, 'rb') as source, open(args.output, 'w', encoding='utf-8') as out:
        for line in source:
            if not line.strip():
                continue
            try:
                command = parse_line(line.decode('utf-8', errors='strict'))
                reply = gateway.process(command)
            except (ValueError, TypeError, UnicodeError):
                reply = {"status": "denied", "code": "malformed"}
            out.write(json.dumps(reply, separators=(',', ':'), ensure_ascii=False) + '\n')
            out.flush()

def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='command', required=True)
    runp = sub.add_parser('run')
    for flag in ('trust', 'state', 'input', 'output'):
        runp.add_argument(f'--{flag}', required=True)
    auditp = sub.add_parser('audit')
    auditp.add_argument('--state', required=True)
    auditp.add_argument('--output', required=True)
    args = parser.parse_args()
    if args.command == 'run':
        run(args)
    elif args.command == 'audit':
        # Scaffold-only placeholder. Full version must export durable effect records.
        with open(args.output, 'w', encoding='utf-8') as out:
            pass

if __name__ == '__main__':
    main()
