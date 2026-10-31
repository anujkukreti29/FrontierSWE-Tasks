"""Gatekeeper starter CLI with initialization and status commands."""
import argparse
import json
import sys
from .primitives import strict_load
from .store import StateError, init_state, status_state


def main():
    p=argparse.ArgumentParser(prog='python -m gatekeeper',
                              description='Gatekeeper starter with incomplete authorization commands')
    subs=p.add_subparsers(dest='command',required=True)
    p_init=subs.add_parser('init');p_init.add_argument('--state',required=True);p_init.add_argument('--trust',required=True)
    ingest=subs.add_parser('ingest');ingest.add_argument('--state',required=True);ingest.add_argument('--file',required=True)
    decide=subs.add_parser('decide');decide.add_argument('--state',required=True);decide.add_argument('--file',required=True);decide.add_argument('--tick',required=True)
    status=subs.add_parser('status');status.add_argument('--state',required=True)
    effects=subs.add_parser('effects');effects.add_argument('--state',required=True);effects.add_argument('--after',default='0');effects.add_argument('--limit',default='100')
    args=p.parse_args()
    try:
        if args.command=='init':
            with open(args.trust,'rb') as f: obj=strict_load(f.read(262145))
            out=init_state(args.state,obj)
        elif args.command=='status': out=status_state(args.state)
        else:
            # Ingestion, decisions, and effect queries remain to be implemented.
            print('{"error":"NOT_IMPLEMENTED"}',file=sys.stderr)
            return 2
        print(json.dumps(out,sort_keys=True,separators=(',',':')))
        return 0
    except StateError as e:
        err=e.code
    except (OSError,UnicodeError):err='IO_ERROR'
    except (ValueError,TypeError,json.JSONDecodeError):err='INVALID_INPUT'
    print(json.dumps({'error':err},separators=(',',':')),file=sys.stderr)
    return 1

if __name__=='__main__':sys.exit(main())
