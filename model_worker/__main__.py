"""Command-line entry point for the bounded local model worker."""

import argparse

from .feature_frontend import FeatureFrontendOperator
from .worker import DeterministicTestOperator, Limits, Worker, serve_unix


def main() -> None:
    parser = argparse.ArgumentParser(description="Serve the local WMW1 model protocol")
    parser.add_argument("--socket", required=True, help="new Unix-domain socket path")
    parser.add_argument(
        "--operator",
        required=True,
        choices=("deterministic-test", "feature-frontend"),
        help="explicit numerical operator",
    )
    arguments = parser.parse_args()
    operator = (
        DeterministicTestOperator()
        if arguments.operator == "deterministic-test"
        else FeatureFrontendOperator()
    )
    serve_unix(arguments.socket, Worker(operator, Limits()))


if __name__ == "__main__":
    main()
