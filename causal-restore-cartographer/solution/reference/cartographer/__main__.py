"""Operator command-line entry point."""
import argparse
from .recover import recover


def main():
    p = argparse.ArgumentParser(prog="cartographer")
    sub = p.add_subparsers(dest="command", required=True)
    r = sub.add_parser("recover")
    r.add_argument("--input", required=True)
    r.add_argument("--output", required=True)
    args = p.parse_args()
    if args.command == "recover":
        recover(args.input, args.output)


if __name__ == "__main__":
    main()
