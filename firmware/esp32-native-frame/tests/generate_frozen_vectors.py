from pathlib import Path
import sys


FIXTURES = (
    ("CAPABILITIES", "capabilities-v1.hex"),
    ("CSI_NON_HT", "csi-non-ht-3-pairs.hex"),
    ("CSI_HT", "csi-ht-5-pairs-first-invalid.hex"),
    ("CSI_HT_STBC", "csi-ht-stbc-7-pairs.hex"),
    ("HEALTH", "health-v1.hex"),
)


def main() -> None:
    fixture_dir = Path(sys.argv[1])
    output = Path(sys.argv[2])
    lines = ["#ifndef FROZEN_VECTORS_H", "#define FROZEN_VECTORS_H", ""]
    for name, filename in FIXTURES:
        data = bytes.fromhex((fixture_dir / filename).read_text(encoding="ascii"))
        values = ", ".join(f"0x{byte:02x}" for byte in data)
        lines.extend(
            (
                f"static const unsigned char FROZEN_{name}[] = {{{values}}};",
                f"#define FROZEN_{name}_BYTES {len(data)}U",
                "",
            )
        )
    lines.append("#endif")
    output.write_text("\n".join(lines) + "\n", encoding="ascii")


if __name__ == "__main__":
    main()
