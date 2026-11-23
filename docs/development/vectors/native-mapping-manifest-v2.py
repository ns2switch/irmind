"""Independent specification vectors for a tiny synthetic production graph."""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path

MASK = 31


def raw(n):
    return n.to_bytes(4, "big")


def label(s):
    b = s.encode("utf-8")
    return raw(len(b)) + b


def digest(data):
    return sha256(data.encode("utf-8")).digest()


def unit(name, version, kind, source, content, context, features, settings):
    return name, version, kind, source, content, context, tuple(sorted(features)), digest(settings)


def manifest(sample):
    nodes = sorted(sample["units"])
    indexes = {node[0]: index for index, node in enumerate(nodes)}
    edges = sorted((indexes[a], indexes[b], kind, alias) for a, b, kind, alias in sample["edges"])
    files = sorted((indexes[n], kind, path, digest(body)) for n, kind, path, body in sample["inputs"])
    out = bytearray(b"irmind-native-mapping-build-v2\x00")
    out += label(sample["rust"]) + digest(sample["settings"]) + raw(indexes["mapping-example"])
    out += raw(len(nodes))
    for name, version, kind, origin, content, context, features, effective in nodes:
        out += label(name) + label(version) + bytes([kind]) + label(origin) + content
        out += bytes([context]) + raw(len(features)) + b"".join(map(label, features))
        out += effective + bytes([MASK])
    out += raw(len(edges))
    for parent, child, kind, alias in edges:
        out += raw(parent) + raw(child) + bytes([kind]) + label(alias) + bytes([MASK])
    out += raw(len(files))
    for owner, kind, path, content in files:
        out += raw(owner) + bytes([kind]) + label(path) + content + bytes([MASK])
    return bytes(out)


BASE = {
    "rust": "1.97.1",
    "settings": "panic=unwind;overflow-checks=true",
    "units": [
        unit("mapping-example", "1.0.0", 0, "crates/mapping-example", bytes(32), 0, (),
             "edition=2024;depends=fields;build=generator"),
        unit("fields", "2.0.0", 1, "https://index.example.invalid", bytes.fromhex("11" * 32),
             0, ["numeric"], "edition=2024;numeric=true"),
        unit("generator", "1.0.0", 0, "crates/generator", bytes(32), 1, (),
             "edition=2024;lib=true"),
    ],
    "edges": [("mapping-example", "fields", 0, "fields"),
              ("mapping-example", "generator", 1, "generator")],
    "inputs": [("mapping-example", 0, "src/lib.rs", "mapping source\n"),
               ("mapping-example", 1, "outputs/table.bin", "deterministic table\n"),
               ("generator", 0, "src/lib.rs", "generator source\n")],
    "unrelated_lock": {"url": "2.5.8", "form_urlencoded": "1.2.2"},
    "unrelated_members": ["mapping-example", "generator"],
    "dev_dependencies": [],
}


def changed_unit(sample, index, field, value):
    fields = list(sample["units"][index])
    fields[field] = value
    sample["units"][index] = tuple(fields)


def vectors():
    baseline = manifest(BASE)
    output = {"canonical_hex": baseline.hex(), "canonical_size": len(baseline),
              "sha256": sha256(baseline).hexdigest(), "variants": {}}
    for name in ("reordered", "unrelated_lock_update", "workspace_member", "dev_dependency",
                 "source", "version", "checksum", "patch", "feature", "generated"):
        sample = deepcopy(BASE)
        if name == "reordered":
            for key in ("units", "edges", "inputs"):
                sample[key].reverse()
        elif name == "unrelated_lock_update":
            sample["unrelated_lock"] = {"url": "2.5.9", "form_urlencoded": "1.2.3"}
        elif name == "workspace_member":
            sample["unrelated_members"].append("unused")
        elif name == "dev_dependency":
            sample["dev_dependencies"].append("test-only")
        elif name == "source":
            sample["inputs"][0] = ("mapping-example", 0, "src/lib.rs", "modified mapping\n")
        elif name == "version":
            changed_unit(sample, 1, 1, "2.0.1")
        elif name == "checksum":
            changed_unit(sample, 1, 4, bytes.fromhex("22" * 32))
        elif name == "patch":
            sample["units"][1] = unit("fields", "2.0.0", 0, "vendor/fields", bytes(32), 0,
                                      ["numeric"], "edition=2024;numeric=true")
            sample["inputs"].append(("fields", 0, "src/lib.rs", "local patch\n"))
        elif name == "feature":
            changed_unit(sample, 1, 6, ("extra", "numeric"))
        elif name == "generated":
            sample["inputs"][1] = ("mapping-example", 1, "outputs/table.bin", "new table\n")
        encoded = manifest(sample)
        output["variants"][name] = {"sha256": sha256(encoded).hexdigest(),
                                     "matches_base": encoded == baseline}
    return output


if __name__ == "__main__":
    data = vectors()
    expected = Path(__file__).with_suffix(".json")
    if expected.is_file():
        assert json.loads(expected.read_text(encoding="utf-8")) == data
    print(json.dumps(data, indent=2) + "\n", end="")
