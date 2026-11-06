#!/usr/bin/env python3
"""Keep first-party unsafe Rust in the cfg(windows) native containment boundary."""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
RAW = re.compile(r'(?:br|cr|r)(#{0,255})"')


def unsafe_offsets(text):
    out=[]
    i=0
    while i<len(text):
        if text.startswith('//',i):
            end=text.find('\n',i);i=len(text) if end<0 else end;continue
        if text.startswith('/*',i):
            depth=1;i+=2
            while i<len(text) and depth:
                if text.startswith('/*',i):depth+=1;i+=2
                elif text.startswith('*/',i):depth-=1;i+=2
                else:i+=1
            continue
        raw=RAW.match(text,i)
        if raw:
            end=text.find('"'+raw.group(1),raw.end())
            i=len(text) if end<0 else end+1+len(raw.group(1));continue
        if text[i]=='"':
            i+=1
            while i<len(text):
                if text[i]=='\\':i+=2
                elif text[i]=='"':i+=1;break
                else:i+=1
            continue
        if text[i]=="'":
            # Rust lifetimes do not have the closing quote of a character literal.
            char=re.match(r"'(?:\\(?:u\{[0-9a-fA-F_]+\}|x[0-9a-fA-F]{2}|.)|[^'\\])'",text[i:])
            if char:i+=len(char.group());continue
        if text.startswith('unsafe',i):
            before=text[i-1] if i else ''
            after=text[i+6] if i+6<len(text) else ''
            if not (before.isalnum() or before=='_') and not (after.isalnum() or after=='_'):
                out.append(i)
        i+=1
    return out


def inspect(path, text):
    offsets=unsafe_offsets(text)
    if not offsets:return []
    relative=path.as_posix()
    allowed=relative.startswith('crates/process-containment/src/windows/') or relative=='crates/process-containment/src/windows.rs'
    cfg=bool(re.search(r'^\s*#!\s*\[\s*cfg\s*\(\s*windows\s*\)\s*\]',text,re.M))
    if allowed and cfg:return []
    return [f'{relative}:{text.count(chr(10),0,offset)+1}: unsafe outside cfg(windows) containment' for offset in offsets]


def main():
    failures=[];count=0
    for top in ('crates','helpers','fuzz','examples','scripts'):
        for path in (ROOT/top).rglob('*.rs'):
            if any(part in ('target','corpus','artifacts') for part in path.relative_to(ROOT).parts):continue
            count+=1
            if path.is_symlink():failures.append(f'{path.relative_to(ROOT)}: Rust source symlink rejected');continue
            failures.extend(inspect(path.relative_to(ROOT),path.read_text(encoding='utf-8')))
    if failures:raise SystemExit('\n'.join(failures))
    print(f'Unsafe boundary passed: {count} first-party Rust files')

if __name__=='__main__':main()
