#!/usr/bin/env python3
"""Inspect synthetic report PDFs with qpdf and Poppler."""
import argparse
import json
import re
import subprocess
from pathlib import Path

FORBIDDEN = {
    "/Action", "/A", "/AA", "/OpenAction", "/URI", "/JavaScript", "/JS",
    "/Launch", "/EmbeddedFile", "/EmbeddedFiles", "/EF", "/Annots", "/Annot",
    "/AcroForm", "/RichMedia",
}
TEXT_OPERAND = re.compile(rb"\((?:[^\\()\r\n]|\\[\\()])*\) Tj T\*")


def command(*args):
    return subprocess.run(args, check=True, stdout=subprocess.PIPE, timeout=30).stdout


def check_names(value):
    if isinstance(value, dict):
        for key, child in value.items():
            check_names(key)
            check_names(child)
    elif isinstance(value, list):
        for child in value:
            check_names(child)
    elif isinstance(value, str) and value.startswith("/"):
        name = re.sub(r"#([a-fA-F0-9]{2})", lambda m: chr(int(m[1], 16)), value)
        if name in FORBIDDEN:
            raise ValueError(f"forbidden PDF name {name}")


def check_object_shapes(objects):
    dictionaries = {
        "/Catalog": {"/Type", "/Pages"},
        "/Pages": {"/Type", "/Count", "/Kids"},
        "/Page": {"/Type", "/Parent", "/MediaBox", "/Resources", "/Contents"},
        "/Font": {"/Type", "/Subtype", "/BaseFont", "/Encoding"},
    }
    for reference, object_data in objects.items():
        if set(object_data) == {"stream"}:
            stream = object_data["stream"]
            if set(stream) != {"dict"} or set(stream["dict"]) != {"/Length"}:
                raise ValueError("unexpected PDF stream dictionary")
            continue
        value = object_data.get("value")
        if not isinstance(value, dict) or set(object_data) != {"value"}:
            raise ValueError("unexpected PDF indirect object")
        allowed = (
            {"/Root", "/Size"} if reference == "trailer"
            else dictionaries.get(value.get("/Type"))
        )
        if set(value) != allowed:
            raise ValueError("unexpected PDF object dictionary")
        if value.get("/Type") == "/Page":
            if value["/Resources"] != {"/Font": {"/F1": "3 0 R"}}:
                raise ValueError("unexpected PDF page resources")
        if value.get("/Type") == "/Font":
            if value["/Subtype"] != "/Type1" or value["/BaseFont"] != "/Courier" or value["/Encoding"] != "/WinAnsiEncoding":
                raise ValueError("unexpected PDF font")

def check_text_stream(stream):
    lines = stream.split(b"\n")
    if (
        lines[:4] != [b"BT", b"/F1 10 Tf", b"12 TL", b"48 750 Td"]
        or lines[-2:] != [b"ET", b""]
        or not all(TEXT_OPERAND.fullmatch(line) for line in lines[4:-2])
    ):
        raise ValueError("unexpected PDF page content operator")


def check_pdf(path, qpdf, pdftotext):
    command(qpdf, "--check", path)
    snapshot = json.loads(command(qpdf, "--json=2", "--json-key=qpdf", "--json-key=pages", path))
    if snapshot["version"] != 2:
        raise ValueError("unexpected qpdf JSON version")
    _, objects = snapshot["qpdf"]
    check_names(objects)
    check_object_shapes(objects)
    streams = {reference for page in snapshot["pages"] for reference in page["contents"]}
    if len(snapshot["pages"]) < 2 or not streams:
        raise ValueError("expected a multipage report with text streams")
    if {key[4:] for key, obj in objects.items() if "stream" in obj} != streams:
        raise ValueError("unexpected PDF stream")
    for reference in sorted(streams):
        number, generation, marker = reference.split()
        if marker != "R":
            raise ValueError("invalid content object reference")
        check_text_stream(command(qpdf, f"--show-object={number},{generation}", "--filtered-stream-data", path))
    text = command(pdftotext, "-enc", "UTF-8", path, "-").decode()
    expected = "Informe del incidente" if path.stem.endswith("-es") else "Incident report"
    if expected not in text or "Análisis (literal)" not in text:
        raise ValueError("Poppler did not recover the expected report text")


def test_rejection():
    cases = [
        {"/Action": None},
        {"/S": "/URI"},
        {"/S": "/JavaScript"},
        {"/S": "/Launch"},
        {"/Type": "/EmbeddedFile"},
        {"/Type": "/Annot"},
        {"/Annots": []},
        {"nested": [{"/Type": "/#41nnot"}]},
    ]
    for fixture in cases:
        try:
            check_names(fixture)
        except ValueError:
            continue
        raise ValueError("active PDF structure passed the rejection check")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--qpdf", default="qpdf")
    parser.add_argument("--pdftotext", default="pdftotext")
    options = parser.parse_args()
    test_rejection()
    for locale in ("en", "es"):
        path = options.directory / f"report-{locale}.pdf"
        check_pdf(path, options.qpdf, options.pdftotext)
        print(f"{path.name}: qpdf structure and page streams + Poppler text passed")


if __name__ == "__main__":
    main()
