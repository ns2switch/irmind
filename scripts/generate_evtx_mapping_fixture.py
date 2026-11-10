#!/usr/bin/env python3
"""Synthetic provider-qualified EVTX fixtures; no captured Windows data."""
from pathlib import Path
from generate_evtx_fixture import make

ROOT = Path(__file__).resolve().parents[1] / 'crates/testkit/fixtures/mapping-evtx/source'
SECURITY = [4624, 4625, 4634, 4648, 4672, 4688, 4697, 4720, 4722, 4724, 4728, 4732, 4756, 4768, 4769, 4771, 4776]


def security(event):
    fields = [('SubjectUserName', 'operator'), ('SubjectUserSid', 'S-1-5-21-1000'),
              ('SubjectDomainName', 'LAB'), ('TargetUserName', 'alice'),
              ('TargetUserSid', 'S-1-5-21-1001'), ('TargetDomainName', 'LAB')]
    if event in (4728, 4732, 4756):
        fields = [(name, 'Synthetic Operators' if name == 'TargetUserName' else value) for name, value in fields]
        fields += [('TargetSid', 'S-1-5-32-544'), ('MemberName', 'alice'), ('MemberSid', 'S-1-5-21-1002')]
    if event in (4768, 4771):
        fields = [('TargetSid' if name == 'TargetUserSid' else name, value) for name, value in fields]
    if event in (4771, 4776):
        fields = [(name, value) for name, value in fields if name != "TargetDomainName"]
    if event != 4776:
        fields += [('IpAddress', '203.0.113.77'), ('IpPort', '49152')]
    if event == 4688:
        fields += [('NewProcessId', '0x4d2'), ('NewProcessName', r'C:\Windows\System32\cmd.exe'),
                   ('ProcessId', '0x42'), ('ParentProcessName', r'C:\Windows\explorer.exe'),
                   ('CommandLine', 'cmd.exe /c echo synthetic')]
    if event == 4697:
        fields += [('ServiceFileName', r'C:\synthetic\service.exe')]
    return fields


def sysmon(event):
    fields = [('User', 'LAB\\alice'), ('ProcessGuid', '{00000001-0002-0003-0004-000000000005}'),
              ('ProcessId', '1234'), ('Image', r'C:\Windows\System32\cmd.exe')]
    if event == 1:
        fields += [('ParentProcessGuid', '{00000006-0007-0008-0009-000000000010}'),
                   ('ParentProcessId', '42'), ('ParentImage', r'C:\Windows\explorer.exe'),
                   ('CommandLine', 'cmd.exe /c echo synthetic')]
    if event == 3:
        fields += [('SourceIp', '203.0.113.77'), ('DestinationIp', '198.51.100.42'),
                   ('SourcePort', '49152'), ('DestinationPort', '443'), ('Protocol', 'tcp')]
    if event == 11:
        fields += [('TargetFilename', r'C:\synthetic\example.txt')]
    if event == 13:
        fields += [('TargetObject', r'HKCU\Software\Synthetic')]
    if event == 22:
        fields += [('QueryName', 'example.test'), ('QueryStatus', '0')]
    return fields


def main():
    ROOT.mkdir(parents=True, exist_ok=True)
    for name, channel, provider, ids, fields in [
        ('authentication', 'Security', 'Microsoft-Windows-Security-Auditing', [4625], security),
        ('security', 'Security', 'Microsoft-Windows-Security-Auditing', SECURITY, security),
        ('system', 'System', 'Service Control Manager', [7045], lambda _: [('ImagePath', r'C:\synthetic\service.exe'), ('AccountName', 'LocalSystem')]),
        ('powershell', 'Microsoft-Windows-PowerShell/Operational', 'Microsoft-Windows-PowerShell', [4103, 4104], lambda _: [('ScriptBlockText', 'Write-Output synthetic')]),
        ('sysmon', 'Microsoft-Windows-Sysmon/Operational', 'Microsoft-Windows-Sysmon', [1, 3, 11, 13, 22], sysmon),
    ]:
        (ROOT / f'{name}.evtx').write_bytes(make(channel, ids, provider=provider, fields=fields))


if __name__ == '__main__':
    main()
