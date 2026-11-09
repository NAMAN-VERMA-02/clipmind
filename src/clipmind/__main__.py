import argparse
import sys

from clipmind import __version__


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="clipmind", description="Private clipboard history for Windows.")
    parser.add_argument("--version", action="version", version=f"clipmind {__version__}")
    parser.parse_args(argv)
    return 0


if __name__ == "__main__":
    sys.exit(main())
