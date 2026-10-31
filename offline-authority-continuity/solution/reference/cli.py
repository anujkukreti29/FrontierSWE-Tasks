"""CLI for the complete reference implementation."""
import argparse
import json
import sqlite3
from .canonical import parse_line
from .gateway import Gateway


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest='cmd',required=True)
    r = sub.add_parser('run')
    for field in ('trust','state','input','output'):
        r.add_argument('--'+field,required=True)
    a = sub.add_parser('audit')
    for field in ('state','output'):
        a.add_argument('--'+field,required=True)
    args = ap.parse_args()
    if args.cmd == 'audit':
        db = sqlite3.connect(f'file:{args.state}?mode=ro',uri=True)
        rows = db.execute('SELECT request_id,site,principal,asset,action,prepare_hash,commit_tick '
                          'FROM effects ORDER BY request_id')
        with open(args.output,'w',encoding='utf-8') as out:
            for row in rows:
                out.write(json.dumps(dict(zip(('request_id','site','principal','asset','action',
                       'prepare_hash','commit_tick'),row)),ensure_ascii=False,separators=(',',':'))+'\n')
        return
    gateway = Gateway(args.trust,args.state)
    with open(args.input,'rb') as inp, open(args.output,'w',encoding='utf-8') as out:
        for line in inp:
            if not line.strip():
                continue
            try:
                response = gateway.process(parse_line(line.decode('utf-8','strict')))
            except (ValueError,TypeError,UnicodeError):
                response = {'status':'denied','code':'malformed'}
            out.write(json.dumps(response,ensure_ascii=False,separators=(',',':'))+'\n')
            out.flush()


if __name__ == '__main__':
    main()
