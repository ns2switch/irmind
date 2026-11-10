#!/usr/bin/env python3
"""Generate small synthetic EVTX records from the documented file/BinXML layout."""
import datetime
import json
import struct
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GROUPS = {
    "Security": [4624, 4625, 4634, 4648, 4672, 4688, 4697, 4698, 4720, 4732, 4768, 4769, 4776, 1102],
    "System": [7045],
    "Microsoft-Windows-PowerShell/Operational": [4103, 4104],
    "Microsoft-Windows-Sysmon/Operational": [1, 3, 7, 8, 10, 11, 12, 13, 22, 23],
}

class Xml:
    def __init__(self, base):
        self.base = base
        self.data = bytearray(b"\x0f\x01\x01\x00")
    def name(self, name):
        encoded = name.encode("utf-16le")
        self.data += struct.pack("<IIHH", self.base + len(self.data) + 4, 0, 0, len(encoded)//2)
        self.data += encoded + b"\0\0"
    def start(self, name):
        self.data += b"\x01" + struct.pack("<I", 0)
        self.name(name)
        self.data += b"\x02"
    def text(self, name, value):
        self.start(name)
        text = str(value).encode("utf-16le")
        self.data += b"\x05\x01" + struct.pack("<H", len(text)//2) + text + b"\x04"
    def data_field(self, name, value):
        self.data += b"\x41" + struct.pack("<I", 0)
        self.name("Data")
        self.data += struct.pack("<I", 0) + b"\x06"
        self.name("Name")
        attr = str(name).encode("utf-16le")
        self.data += b"\x05\x01" + struct.pack("<H", len(attr)//2) + attr
        self.data += b"\x02"
        text = str(value).encode("utf-16le")
        self.data += b"\x05\x01" + struct.pack("<H", len(text)//2) + text + b"\x04"
    def provider(self, name):
        self.data += b"\x41" + struct.pack("<I", 0)
        self.name("Provider")
        self.data += struct.pack("<I", 0) + b"\x06"
        self.name("Name")
        encoded = name.encode("utf-16le")
        self.data += b"\x05\x01" + struct.pack("<H", len(encoded)//2) + encoded + b"\x03"
    def end(self):
        self.data += b"\x04"


def make(channel, ids, *, provider=None, fields=None):
    file = bytearray(4096 + 65536)
    def put(at, fmt, value):
        struct.pack_into(fmt, file, at, value)
    file[:8] = b"ElfFile\0"
    for at, fmt, value in [(24,"<Q",len(ids)+1),(32,"<I",128),(36,"<H",1),(38,"<H",3),(40,"<H",4096),(42,"<H",1)]:
        put(at,fmt,value)
    put(124,"<I",zlib.crc32(file[:120]))
    file[4096:4104] = b"ElfChnk\0"
    cursor=512
    ticks = (int(datetime.datetime(2026,11,1,12,tzinfo=datetime.timezone.utc).timestamp()) + 11644473600)*10_000_000
    for index,event in enumerate(ids):
        last=cursor
        xml=Xml(cursor+24)
        xml.start("Event");xml.start("System")
        if provider is not None: xml.provider(provider)
        for name,value in [("EventID",event),("Channel",channel),("Computer","synthetic-endpoint"),("EventRecordID",index+1)]:
            xml.text(name,value)
        xml.end();xml.start("EventData")
        for name,value in (fields(event) if fields is not None else [("TargetUserName","synthetic-user"),("User","synthetic-user"),("Image",r"C:\Windows\System32\cmd.exe"),("CommandLine","cmd.exe /c synthetic"),("IpAddress","203.0.113.77"),("SourceIp","203.0.113.77"),("DestinationIp","198.51.100.42"),("SourcePort",49152),("DestinationPort",443),("LogonType",3),("ProcessId",1234),("ServiceName","SyntheticService"),("TaskName","SyntheticTask"),("TargetObject",r"HKCU\Software\Synthetic"),("ScriptBlockText","Write-Output synthetic")]):
            xml.data_field(name,value)
        xml.end();xml.end();xml.data+=b"\x00"
        size=24+len(xml.data)+4
        assert cursor+size<=65536
        at=4096+cursor
        file[at:at+4]=b"\x2a\x2a\0\0"
        put(at+4,"<I",size);put(at+8,"<Q",index+1);put(at+16,"<Q",ticks+index*10+7)
        file[at+24:at+size-4]=xml.data
        put(at+size-4,"<I",size)
        cursor+=size
    for at,value in [(8,1),(16,len(ids)),(24,1),(32,len(ids))]:put(4096+at,"<Q",value)
    for at,value in [(40,128),(44,last),(48,cursor)]:put(4096+at,"<I",value)
    put(4096+52,"<I",zlib.crc32(file[4096+512:4096+cursor]))
    put(4096+124,"<I",zlib.crc32(file[4096:4096+120]+file[4096+128:4096+512]))
    return bytes(file)


def main():
    root=ROOT/"crates/testkit/fixtures/parser-evtx"
    (root/"source").mkdir(parents=True,exist_ok=True)
    (root/"private").mkdir(exist_ok=True)
    expected=[]
    for channel,ids in GROUPS.items():
        name=channel.split('/')[0]+'.evtx'
        (root/"source"/name).write_bytes(make(channel,ids))
        expected.append({"source":name,"channel":channel,"events":ids,"host":"synthetic-endpoint","ip":"203.0.113.77","techniques":["T1078","T1021.002","T1543.003"]})
    (root/"private/ground-truth.json").write_text(json.dumps({
        "synthetic":True,"episode_id":"synthetic-windows-lateral-service-001",
        "provider":"windows","episodes":expected,
        "malicious_events":["logon_success","service_install"],
        "malicious_entities":["synthetic-endpoint","synthetic-user","203.0.113.77"],
        "attack_path":[{"type":"ip","value":"203.0.113.77"},{"type":"host","value":"synthetic-endpoint"},{"type":"process","value":r"C:\Windows\System32\cmd.exe"}],
        "mitre_attack":["T1078","T1021.002","T1543.003"],
        "acceptable_conclusions":["Synthetic network logon (4624, type 3) followed by service-install records (4697 and 7045). These records alone do not prove remote command execution or exfiltration."],
        "private_marker":"IRMind-EVTX-synthetic-evaluator-only",
    },indent=2)+'\n')
    (ROOT/"helpers/evtx/fuzz/seeds/security.evtx").write_bytes(make('Security',[4624,4697]))

if __name__=='__main__':main()
