#!/usr/bin/env python3
import hashlib
import json
import struct
import sys
from pathlib import Path


DOMAIN = b"esp-idf-wifi-csi-abi-v1\0"


def main():
    output_header, output_json, *inputs = map(Path, sys.argv[1:])
    framed = bytearray(DOMAIN)
    files = []
    for source in inputs:
        data = source.read_bytes()
        framed.extend(struct.pack("<Q", len(data)))
        framed.extend(data)
        files.append({"path": source.name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    digest = hashlib.sha256(framed).digest()
    output_header.write_text(
        "#ifndef CAPABILITY_BUILD_FACTS_H\n#define CAPABILITY_BUILD_FACTS_H\n\n"
        "static const unsigned char IDF_WIFI_ABI_DIGEST[32] = {\n    "
        + ", ".join(f"0x{byte:02x}" for byte in digest)
        + "\n};\n\n#endif\n",
        encoding="ascii",
    )
    output_json.write_text(json.dumps({
        "schema": 1,
        "domain": DOMAIN[:-1].decode("ascii"),
        "length_encoding": "u64-le",
        "files": files,
        "idf_wifi_abi_digest": digest.hex(),
    }, indent=2) + "\n", encoding="ascii")


if __name__ == "__main__":
    main()
