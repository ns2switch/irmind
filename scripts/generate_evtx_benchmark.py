#!/usr/bin/env python3
"""Generate an entirely synthetic Security chunk with event-specific fields."""
from pathlib import Path
import struct
import zlib
from generate_evtx_fixture import Xml

FIELDS = {
    4624: [('TargetUserName', 'synthetic-user'), ('TargetDomainName', 'SYNTHETIC'),
           ('TargetUserSid', 'S-1-5-21-1000-1000-1000-1001'), ('LogonType', '3'),
           ('IpAddress', '203.0.113.77'), ('IpPort', '49152'),
           ('AuthenticationPackageName', 'Kerberos'), ('TargetLogonId', '0x123456')],
    4625: [('TargetUserName', 'synthetic-user'), ('TargetDomainName', 'SYNTHETIC'),
           ('LogonType', '3'), ('IpAddress', '203.0.113.77'),
           ('Status', '0xc000006d'), ('SubStatus', '0xc000006a')],
    4688: [('SubjectUserName', 'synthetic-user'), ('NewProcessName', r'C:\Windows\System32\cmd.exe'),
           ('NewProcessId', '0x1234'), ('CommandLine', 'cmd.exe /c echo synthetic'),
           ('ParentProcessName', r'C:\Windows\explorer.exe'), ('TokenElevationType', '%%1936')],
    4634: [('TargetUserName', 'synthetic-user'), ('TargetLogonId', '0x123456'), ('LogonType', '3')],
    4672: [('SubjectUserName', 'synthetic-user'), ('SubjectLogonId', '0x123456'),
           ('PrivilegeList', 'SeDebugPrivilege SeImpersonatePrivilege')],
}


def generate(dense=False):
    file = bytearray(4096 + 65536)
    file[:8] = b'ElfFile\0'
    file[4096:4104] = b'ElfChnk\0'
    cursor, count, last = 512, 0, 512
    ids = (4624, 4625, 4688, 4634, 4672)
    while not dense or count < 128:
        event = ids[count % len(ids)] if not dense else 4624
        xml = Xml(cursor + 24)
        xml.start('Event'); xml.start('System')
        fields = [('EventID', event), ('Computer', 'synthetic-endpoint'), ('EventRecordID', f'{count + 1:020}')]
        if not dense:
            fields.insert(1, ('Channel', 'Security'))
        for name, value in fields:
            xml.text(name, value)
        xml.end(); xml.start('EventData')
        for name, value in ([("TargetUserName", "synthetic-user")] if dense else FIELDS[event]):
            xml.data_field(name, value)
        xml.end(); xml.end(); xml.data += b'\x00'
        size = 24 + len(xml.data) + 4
        if cursor + size > 65536:
            break
        last = cursor
        offset = 4096 + cursor
        struct.pack_into('<4sIQQ', file, offset, b'\x2a\x2a\0\0', size, count + 1,
                         134380080000000007 + count * 1000000)
        file[offset + 24:offset + size - 4] = xml.data
        struct.pack_into('<I', file, offset + size - 4, size)
        count += 1
        cursor += size
    for offset, fmt, value in [(24, '<Q', count + 1), (32, '<I', 128), (36, '<H', 1),
                                (38, '<H', 3), (40, '<H', 4096), (42, '<H', 1)]:
        struct.pack_into(fmt, file, offset, value)
    struct.pack_into('<I', file, 124, zlib.crc32(file[:120]))
    for offset, value in [(8, 1), (16, count), (24, 1), (32, count)]:
        struct.pack_into('<Q', file, 4096 + offset, value)
    for offset, value in [(40, 128), (44, last), (48, cursor)]:
        struct.pack_into('<I', file, 4096 + offset, value)
    struct.pack_into('<I', file, 4096 + 52, zlib.crc32(file[4096 + 512:4096 + cursor]))
    struct.pack_into('<I', file, 4096 + 124,
                     zlib.crc32(file[4096:4096 + 120] + file[4096 + 128:4096 + 512]))
    return bytes(file), count


if __name__ == '__main__':
    root = Path(__file__).resolve().parents[1] / 'helpers/evtx/examples/large_support'
    for dense, name in [(False, 'Security.evtx'), (True, 'SecurityDense.evtx')]:
        data, records = generate(dense)
        if dense and records != 128:
            raise ValueError('dense fixture must fit exactly 128 records per chunk')
        (root / name).write_bytes(data)
        print(f'{name}: {len(data)} bytes; {records} records per chunk')
