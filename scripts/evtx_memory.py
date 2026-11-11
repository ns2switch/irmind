"""Development-only process memory sampling; no third-party packages."""
import os
from pathlib import Path


def linux_processes():
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            fields = dict(line.split(':', 1) for line in (entry / 'status').read_text().splitlines())
            yield (int(entry.name), int(fields['PPid']), fields['Name'].strip(),
                   int(fields.get('VmHWM', '0 kB').split()[0]) * 1024)
        except (FileNotFoundError, ProcessLookupError, PermissionError, KeyError):
            continue


def windows_processes(names=('large_collection.exe', 'irmind-evtx.exe')):
    import ctypes as c
    from ctypes import wintypes as w

    class Entry(c.Structure):
        _fields_ = [('size', w.DWORD), ('usage', w.DWORD), ('pid', w.DWORD),
                    ('heap', c.c_size_t), ('module', w.DWORD), ('threads', w.DWORD),
                    ('parent', w.DWORD), ('priority', w.LONG), ('flags', w.DWORD),
                    ('name', w.WCHAR * 260)]

    class Memory(c.Structure):
        _fields_ = [('size', w.DWORD), ('faults', w.DWORD),
                    ('peak', c.c_size_t), ('working', c.c_size_t),
                    ('peak_page', c.c_size_t), ('page', c.c_size_t),
                    ('peak_nonpage', c.c_size_t), ('nonpage', c.c_size_t),
                    ('pagefile', c.c_size_t), ('peak_pagefile', c.c_size_t)]

    kernel = c.WinDLL('kernel32', use_last_error=True)
    psapi = c.WinDLL('psapi', use_last_error=True)
    kernel.CreateToolhelp32Snapshot.argtypes = [w.DWORD, w.DWORD]
    kernel.CreateToolhelp32Snapshot.restype = w.HANDLE
    kernel.Process32FirstW.argtypes = kernel.Process32NextW.argtypes = [w.HANDLE, c.POINTER(Entry)]
    kernel.Process32FirstW.restype = kernel.Process32NextW.restype = w.BOOL
    kernel.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
    kernel.OpenProcess.restype = w.HANDLE
    kernel.CloseHandle.argtypes = [w.HANDLE]
    kernel.CloseHandle.restype = w.BOOL
    psapi.GetProcessMemoryInfo.argtypes = [w.HANDLE, c.POINTER(Memory), w.DWORD]
    psapi.GetProcessMemoryInfo.restype = w.BOOL
    snapshot = kernel.CreateToolhelp32Snapshot(2, 0)
    if snapshot == c.c_void_p(-1).value:
        raise OSError('cannot enumerate benchmark process memory')
    entry = Entry()
    entry.size = c.sizeof(entry)
    try:
        present = kernel.Process32FirstW(snapshot, c.byref(entry))
        while present:
            if entry.name.lower() in names:
                handle = kernel.OpenProcess(0x410, False, entry.pid)
                if handle:
                    try:
                        memory = Memory()
                        memory.size = c.sizeof(memory)
                        if psapi.GetProcessMemoryInfo(handle, c.byref(memory), memory.size):
                            yield entry.pid, entry.parent, entry.name, memory.peak
                    finally:
                        kernel.CloseHandle(handle)
            present = kernel.Process32NextW(snapshot, c.byref(entry))
    finally:
        kernel.CloseHandle(snapshot)


def processes():
    return windows_processes() if os.name == 'nt' else linux_processes()
