#!/usr/bin/env python3
"""Print only imported DLL names from a built helper after a native launch failure."""
import json
import struct
import sys
from pathlib import Path


def imports(data):
    def u16(offset): return struct.unpack_from('<H', data, offset)[0]
    def u32(offset): return struct.unpack_from('<I', data, offset)[0]
    pe = u32(0x3c)
    assert data[:2] == b'MZ' and data[pe:pe + 4] == b'PE\0\0'
    optional = pe + 24
    directories = optional + (112 if u16(optional) == 0x20b else 96)
    sections = optional + u16(pe + 20)
    count = u16(pe + 6)
    assert 1 <= count <= 96

    def position(rva):
        for index in range(count):
            section = sections + index * 40
            address, size, start = u32(section + 12), u32(section + 16), u32(section + 20)
            if address <= rva < address + size:
                return start + rva - address
        raise ValueError('import RVA is outside raw sections')

    cursor = position(u32(directories + 8))
    names = []
    for _ in range(256):
        if data[cursor:cursor + 20] == bytes(20):
            return sorted(set(names))
        name = position(u32(cursor + 12))
        end = data.index(0, name, min(name + 256, len(data)))
        text = data[name:end].decode('ascii')
        assert text and all(c.isalnum() or c in '._-' for c in text)
        names.append(text)
        cursor += 20
    raise ValueError('too many import descriptors')


if __name__ == '__main__':
    path = Path(sys.argv[1])
    if not path.is_file():
        print('No helper executable was built.')
    else:
        assert path.stat().st_size <= 50 * 1024 * 1024
        print(json.dumps({'direct_dll_imports': imports(path.read_bytes())}, sort_keys=True))
