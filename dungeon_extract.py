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

STRATEGY_XOR_LE = "xor-key-le"
STRATEGY_XOR_BE = "xor-key-be"
STRATEGY_XOR_LE_INVERT = "xor-key-le-invert"
STRATEGY_LCG = "xor-lcg"
SUPPORTED_STRATEGIES = (
    STRATEGY_XOR_LE,
    STRATEGY_XOR_BE,
    STRATEGY_XOR_LE_INVERT,
    STRATEGY_LCG,
)


def _read_cstring(data: bytes) -> str:
    return data.split(b"\x00", 1)[0].decode("utf-8", errors="replace")


def _xor_data(data: bytes, key: int, endian: str = "<") -> bytes:
    key_bytes = struct.pack(f"{endian}I", key)
    return bytes(b ^ key_bytes[i % 4] for i, b in enumerate(data))


def _xor_lcg(data: bytes, key: int) -> bytes:
    seed = key & 0xFFFFFFFF
    out = bytearray()
    for b in data:
        seed = (214013 * seed + 2531011) & 0xFFFFFFFF
        out.append(b ^ ((seed >> 16) & 0xFF))
    return bytes(out)


def _decrypt_payload(data: bytes, key: int, strategy: str) -> bytes:
    if strategy == STRATEGY_XOR_LE:
        return _xor_data(data, key, "<")
    if strategy == STRATEGY_XOR_BE:
        return _xor_data(data, key, ">")
    if strategy == STRATEGY_XOR_LE_INVERT:
        return bytes(b ^ 0xFF for b in _xor_data(data, key, "<"))
    if strategy == STRATEGY_LCG:
        return _xor_lcg(data, key)
    raise ValueError(f"Estrategia desconhecida: {strategy}")


def _next_offset(offsets: list[int], current: int, blob_len: int) -> int:
    candidates = [off for off in offsets if off > current]
    return min(candidates) if candidates else blob_len


def extract_archive(
    src: Path,
    dest: Path,
    manifest_path: Path | None,
    strategy: str,
    all_strategies: bool,
) -> None:
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
    strategy_list = list(SUPPORTED_STRATEGIES) if all_strategies else [strategy]
    if all_strategies:
        for strat in strategy_list:
            (dest / strat).mkdir(parents=True, exist_ok=True)

    for index in range(file_count):
        entry_offset = entry_table_offset + index * ENTRY_SIZE
        name = _read_cstring(blob[entry_offset : entry_offset + NAME_SIZE])
        if not name:
            raise ValueError(f"Entrada {index} sem nome no arquivo.")
        file_order.append(name)

        data_offset = offsets[index]
        if data_offset == 0:
            print(f"Aviso: {name} sem dados no arquivo.", file=sys.stderr)
            if all_strategies:
                for strat in strategy_list:
                    (dest / strat / name).write_bytes(b"")
            else:
                (dest / name).write_bytes(b"")
            continue
        if data_offset + 12 > len(blob):
            raise ValueError(f"Offset invalido para {name}.")
        block_type, size, key = struct.unpack_from("<III", blob, data_offset)
        if block_type != 1:
            raise ValueError(f"Tipo inesperado {block_type} em {name}.")

        payload_start = data_offset + 12
        payload_end = payload_start + size
        max_end = _next_offset(valid_offsets, data_offset, len(blob))
        if payload_end > max_end:
            print(f"Aviso: tamanho acima do limite para {name}.", file=sys.stderr)
            payload_end = max_end
        encrypted = blob[payload_start:payload_end]
        if all_strategies:
            for strat in strategy_list:
                decrypted = _decrypt_payload(encrypted, key, strat)
                (dest / strat / name).write_bytes(decrypted)
        else:
            decrypted = _decrypt_payload(encrypted, key, strategy)
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
    parser.add_argument(
        "--strategy",
        choices=SUPPORTED_STRATEGIES,
        default=STRATEGY_XOR_LE,
        help="Estrategia de descriptografia para os payloads",
    )
    parser.add_argument(
        "--all-strategies",
        action="store_true",
        help="Gerar saidas para todas as estrategias suportadas",
    )
    args = parser.parse_args()
    extract_archive(args.src, args.dest, args.manifest, args.strategy, args.all_strategies)


if __name__ == "__main__":
    main()
