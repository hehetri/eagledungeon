#!/usr/bin/env python3
"""Pack decrypted files into dungeon.bin using stored metadata."""

from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path


HEADER_SIZE = 16
ENTRY_SIZE = 260
NAME_SIZE = 64
OFFSET_TABLE_PADDING = 16


def _write_cstring(name: str, size: int) -> bytes:
    raw = name.encode("utf-8")
    if len(raw) > size:
        raise ValueError(f"Nome muito longo: {name}")
    return raw + b"\x00" * (size - len(raw))


def _xor_data(data: bytes, key: int) -> bytes:
    key_bytes = struct.pack("<I", key)
    return bytes(b ^ key_bytes[i % 4] for i, b in enumerate(data))


def _load_manifest(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def pack_archive(src_dir: Path, manifest_path: Path, dest: Path) -> None:
    manifest = _load_manifest(manifest_path)
    file_order = manifest.get("file_order")
    if not file_order:
        raise ValueError("Manifesto sem lista de arquivos.")

    header = manifest.get("header", {})
    header0 = int(header.get("header0", 0))
    header1 = int(header.get("header1", 0))
    header2 = int(header.get("header2", 0))
    file_count = int(header.get("file_count", len(file_order)))
    if file_count != len(file_order):
        raise ValueError("file_count no manifesto nao bate com file_order.")

    key = int(manifest.get("crypto", {}).get("key", 0))
    if not key:
        raise ValueError("Chave de criptografia ausente no manifesto.")

    entries = []
    data_blocks = []
    offsets = []

    offset_table_offset = HEADER_SIZE + file_count * ENTRY_SIZE + OFFSET_TABLE_PADDING
    current_offset = offset_table_offset + file_count * 4

    for name in file_order:
        path = src_dir / name
        if not path.exists():
            raise FileNotFoundError(f"Arquivo ausente: {path}")
        plain = path.read_bytes()
        encrypted = _xor_data(plain, key)
        block = struct.pack("<III", 1, len(encrypted), key) + encrypted
        offsets.append(current_offset)
        data_blocks.append(block)
        current_offset += len(block)
        entries.append(_write_cstring(name, NAME_SIZE) + b"\x00" * (ENTRY_SIZE - NAME_SIZE))

    with dest.open("wb") as handle:
        handle.write(struct.pack("<IIII", header0, header1, header2, file_count))
        for entry in entries:
            handle.write(entry)
        handle.write(b"\x00" * OFFSET_TABLE_PADDING)
        for off in offsets:
            handle.write(struct.pack("<I", off))
        for block in data_blocks:
            handle.write(block)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Reempacota dungeon.bin usando manifesto e arquivos descriptografados",
    )
    parser.add_argument("src_dir", type=Path, help="Diretorio com arquivos .dun")
    parser.add_argument("manifest", type=Path, help="Manifesto gerado pelo extractor")
    parser.add_argument("dest", type=Path, help="Arquivo dungeon.bin de saida")
    args = parser.parse_args()
    pack_archive(args.src_dir, args.manifest, args.dest)


if __name__ == "__main__":
    main()
