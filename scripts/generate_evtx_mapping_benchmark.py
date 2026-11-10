#!/usr/bin/env python3
"""Expand the synthetic provider-qualified fixture to a chronological 1 GiB EVTX."""
from pathlib import Path
import struct
import zlib
import sys


def generate(path):
    fixture = Path(__file__).resolve().parents[1] / 'crates/testkit/fixtures/mapping-evtx/source/security.evtx'
    data = fixture.read_bytes()
    header, chunk = bytearray(data[:4096]), bytearray(data[4096:])
    chunks, records = 16384, 17
    struct.pack_into('<Q', header, 16, chunks - 1)
    struct.pack_into('<Q', header, 24, chunks * records + 1)
    struct.pack_into('<H', header, 42, chunks)
    struct.pack_into('<I', header, 124, zlib.crc32(header[:120]))
    end = struct.unpack_from('<I', chunk, 48)[0]
    epoch = struct.unpack_from('<Q', chunk, 528)[0]
    with path.open('wb') as output:
        output.write(header)
        for part in range(chunks):
            cursor = 512
            ordinal = part * records
            while cursor < end:
                size = struct.unpack_from('<I', chunk, cursor + 4)[0]
                struct.pack_into('<Q', chunk, cursor + 16, epoch + ordinal * 10)
                ordinal += 1
                cursor += size
            struct.pack_into('<I', chunk, 52, zlib.crc32(chunk[512:end]))
            struct.pack_into('<I', chunk, 124, zlib.crc32(chunk[:120] + chunk[128:512]))
            output.write(chunk)
    print(f'synthetic EVTX: bytes={path.stat().st_size} records={chunks * records}')


if __name__ == '__main__':
    generate(Path(sys.argv[1]))
