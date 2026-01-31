#!/usr/bin/env python3
"""Extract files from dungeon.bin archive and decrypt payloads."""

from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path


HEADER_SIZE = 16
ENTRY_SIZE = 260
NAME_SIZE = 64
OFFSET_TABLE_PADDING = 16


def _read_cstring(data: bytes) -> str:
    return data.split(b"\x00", 1)[0].decode("utf-8", errors="replace")


def _xor_data(data: bytes, key: int) -> bytes:
    key_bytes = struct.pack("<I", key)
    return bytes(b ^ key_bytes[i % 4] for i, b in enumerate(data))


def extract_archive(src: Path, dest: Path, manifest_path: Path | None) -> None:
    blob = src.read_bytes()
    if len(blob) < HEADER_SIZE:
        raise ValueError("Arquivo muito pequeno para conter o cabeçalho.")

    header0, header1, header2, file_count = struct.unpack_from("<IIII", blob, 0)
    entry_table_offset = HEADER_SIZE
    entry_table_size = file_count * ENTRY_SIZE
    offsets_table_offset = entry_table_offset + entry_table_size + OFFSET_TABLE_PADDING

    offsets = [
        struct.unpack_from("<I", blob, offsets_table_offset + i * 4)[0]
        for i in range(file_count)
    ]
    valid_offsets = [off for off in offsets if off != 0]
    if not valid_offsets:
        raise ValueError("Tabela de offsets vazia.")
    data_section_offset = min(valid_offsets)

    dest.mkdir(parents=True, exist_ok=True)
    file_order: list[str] = []

    for index in range(file_count):
        entry_offset = entry_table_offset + index * ENTRY_SIZE
        name = _read_cstring(blob[entry_offset : entry_offset + NAME_SIZE])
        if not name:
            raise ValueError(f"Entrada {index} sem nome no arquivo.")
        file_order.append(name)

        data_offset = offsets[index]
        if data_offset == 0:
            print(f"Aviso: {name} sem dados no arquivo.", file=sys.stderr)
            (dest / name).write_bytes(b"")
            continue
        if data_offset + 12 > len(blob):
            raise ValueError(f"Offset invalido para {name}.")
        block_type, size, key = struct.unpack_from("<III", blob, data_offset)
        if block_type != 1:
            raise ValueError(f"Tipo inesperado {block_type} em {name}.")

        payload_start = data_offset + 12
        payload_end = payload_start + size
        if payload_end > len(blob):
            print(f"Aviso: payload truncado para {name}.", file=sys.stderr)
            payload_end = len(blob)
        encrypted = blob[payload_start:payload_end]
        decrypted = _xor_data(encrypted, key)
        (dest / name).write_bytes(decrypted)

    if manifest_path:
        manifest = {
            "header": {
                "header0": header0,
                "header1": header1,
                "header2": header2,
                "file_count": file_count,
            },
            "entry": {
                "entry_size": ENTRY_SIZE,
                "name_size": NAME_SIZE,
                "entry_table_offset": entry_table_offset,
                "offsets_table_offset": offsets_table_offset,
                "data_section_offset": data_section_offset,
            },
            "crypto": {
                "key": struct.unpack_from("<I", blob, offsets[0] + 8)[0]
                if offsets
                else 0,
            },
            "file_order": file_order,
        }
        manifest_path.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extrai e descriptografa dungeon.bin",
    )
    parser.add_argument("src", type=Path, help="Arquivo dungeon.bin")
    parser.add_argument("dest", type=Path, help="Diretorio de saida")
    parser.add_argument(
        "--manifest",
        type=Path,
        help="Salvar metadados para reempacotar depois",
    )
    args = parser.parse_args()
    extract_archive(args.src, args.dest, args.manifest)


if __name__ == "__main__":
    main()
