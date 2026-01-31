#!/usr/bin/env python3
"""Visualize decrypted .dun files as hex/ASCII and optional strings."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


def hexdump(data: bytes, width: int = 16) -> str:
    lines = []
    for offset in range(0, len(data), width):
        chunk = data[offset : offset + width]
        hex_bytes = " ".join(f"{b:02x}" for b in chunk)
        ascii_bytes = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{offset:08x}  {hex_bytes:<{width*3}}  {ascii_bytes}")
    return "\n".join(lines)


def extract_strings(data: bytes, min_len: int) -> list[str]:
    pattern = re.compile(rb"[ -~]{%d,}" % min_len)
    return [match.group(0).decode("utf-8", errors="replace") for match in pattern.finditer(data)]


def main() -> None:
    parser = argparse.ArgumentParser(description="Visualiza um arquivo .dun descriptografado")
    parser.add_argument("src", type=Path, help="Arquivo .dun descriptografado")
    parser.add_argument("--out", type=Path, help="Arquivo de texto para salvar a saida")
    parser.add_argument("--width", type=int, default=16, help="Bytes por linha no hexdump")
    parser.add_argument(
        "--strings",
        action="store_true",
        help="Tambem listar strings ASCII encontradas no arquivo",
    )
    parser.add_argument(
        "--min-len",
        type=int,
        default=4,
        help="Tamanho minimo para strings ASCII",
    )
    args = parser.parse_args()

    data = args.src.read_bytes()
    output = [hexdump(data, width=args.width)]
    if args.strings:
        strings = extract_strings(data, args.min_len)
        output.append("\nStrings encontradas:")
        output.extend(strings if strings else ["(nenhuma string encontrada)"])

    text = "\n".join(output) + "\n"
    if args.out:
        args.out.write_text(text, encoding="utf-8")
    else:
        print(text, end="")


if __name__ == "__main__":
    main()
