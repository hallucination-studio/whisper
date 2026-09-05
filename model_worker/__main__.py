"""Command-line entry point for the bounded local model worker."""

import argparse

from .worker import DeterministicTestOperator, Limits, Worker, serve_unix


def main() -> None:
    parser = argparse.ArgumentParser(description="Serve the local WMW1 model protocol")
    parser.add_argument("--socket", required=True, help="new Unix-domain socket path")
    parser.add_argument(
        "--operator",
        required=True,
        choices=("deterministic-test",),
        help="explicit numerical operator; real model loading is supplied by its integration ticket",
    )
    arguments = parser.parse_args()
    serve_unix(arguments.socket, Worker(DeterministicTestOperator(), Limits()))


if __name__ == "__main__":
    main()
