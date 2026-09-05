# Unified check intentional-failure receipt

This receipt records `make check` at revision
`a331dd5519b5bb4565aa59454c251803ebae7585` rejecting one controlled domain
regression on 2026-09-05 UTC. The recorder archived that clean revision into a
temporary directory, inverted the existing assertion that the retired Host
binary is absent, and ran the same command used by CI. The source checkout was
not modified.

The command exited with status 2 after Cargo reported
`package_has_no_legacy_host_binary_target ... FAILED` and Make reported the
`check-rust` failure. The exact command, mutation, timestamps, platform, exit
status and log digest are in [receipt.json](receipt.json); the captured output
is in [intentional-domain-failure.log](intentional-domain-failure.log).

This negative-path execution proves only that a domain behavior regression is
visible as failure of the unified CI-equivalent command. Because Make stops at
the failing prerequisite, this run did not reach the later firmware build and
does not prove firmware, hardware, RF accuracy or long-duration acceptance.
The ordinary passing gate separately executes the pinned firmware build.

The receipt can be reproduced from its identified revision with:

```sh
python3 scripts/record_check_failure.py /path/to/new-empty-output-directory
```
