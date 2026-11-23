"""Canonical V2 encoding for production native mapping input graphs."""
from collections import defaultdict
from hashlib import sha256
from pathlib import PurePosixPath
import re
import struct

MAGIC = b"irmind-native-mapping-build-v2\0"
TARGETS = (
    "linux-x86_64",
    "linux-aarch64",
    "macos-x86_64",
    "macos-aarch64",
    "windows-x86_64",
)
ALL_TARGETS = (1 << len(TARGETS)) - 1


def _u32(value):
    return struct.pack(">I", value)


def _text(value):
    if not isinstance(value, str):
        raise ValueError("Native mapping manifest text is not a string")
    data = value.encode("utf-8")
    if not 0 < len(data) <= 512 or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("Native mapping manifest text exceeds its bound or contains controls")
    return _u32(len(data)) + data


def _digest(value):
    if not isinstance(value, str) or re.fullmatch("[0-9a-f]{64}", value) is None:
        raise ValueError("Native mapping manifest hash is not lowercase SHA-256")
    return bytes.fromhex(value)


def _bounded_count(items, bound):
    if len(items) > bound:
        raise ValueError(f"Native mapping manifest count exceeds {bound}")
    return _u32(len(items))


def _mask(mask):
    if type(mask) is not int or not 0 < mask <= ALL_TARGETS:
        raise ValueError("Native mapping manifest has an unknown target mask")
    return bytes([mask])


def _enum(value, allowed):
    if type(value) is not int or value not in allowed:
        raise ValueError("Native mapping manifest has an unknown type code")
    return bytes([value])


def portable_path(value):
    path = PurePosixPath(value)
    if (
        not path.parts or path.is_absolute() or value != path.as_posix()
        or any(part in (".", "..") for part in path.parts)
        or any(char in value for char in "\\:")
    ):
        raise ValueError("Native mapping manifest has a nonportable path")
    return value


def _unit_key(unit):
    name, version, kind, source, digest, context, features, manifest = unit
    if features != sorted(set(features)):
        raise ValueError("Native mapping features must be sorted and unique")
    return name, version, kind, source, digest, context, tuple(features), manifest


def _encode_unit(key, mask):
    name, version, source_kind, source, digest, context, features, manifest = key
    if source_kind == 0:
        portable_path(source)
        if digest != "0" * 64:
            raise ValueError("Local mapping packages must commit their file inputs")
    elif source_kind in (1, 2):
        if not source.startswith("https://") or "@" in source or "?" in source:
            raise ValueError("Registry or Git origin must be an uncredentialed canonical HTTPS URL")
        if source_kind == 2:
            url, separator, revision = source.partition("#")
            if not url or not separator or re.fullmatch("[0-9a-f]{40}|[0-9a-f]{64}", revision) is None:
                raise ValueError("Native mapping Git origin must include a full revision")
            if sha256(revision.encode("utf-8")).hexdigest() != digest:
                raise ValueError("Native mapping Git revision hash does not match")
        elif "#" in source:
            raise ValueError("A registry source cannot contain a fragment")
    return (
        _text(name) + _text(version) + _enum(source_kind, (0, 1, 2))
        + _text(source) + _digest(digest) + _enum(context, (0, 1, 2))
        + _bounded_count(features, 128) + b"".join(map(_text, features))
        + _digest(manifest) + _mask(mask)
    )


def encode(rust, settings, root, units, edges, inputs):
    """Encode validated per-target units merged by identity and applicability."""
    nodes = sorted(units)
    if root not in units or units[root] != ALL_TARGETS:
        raise ValueError("The native mapping root must cover all release targets")
    index = {unit: index for index, unit in enumerate(nodes)}
    edge_table = sorted((index[a], index[b], kind, alias, mask)
                        for (a, b, kind, alias), mask in edges.items())
    input_table = sorted((index[unit], kind, path, digest, mask)
                         for (unit, kind, path, digest), mask in inputs.items())

    outgoing = defaultdict(list)
    result = bytearray(MAGIC)
    result += _text(rust) + _digest(settings) + _u32(index[root])
    result += _bounded_count(nodes, 256)
    for node in nodes:
        result += _encode_unit(node, units[node])
    result += _bounded_count(edge_table, 1024)
    for parent, child, kind, alias, mask in edge_table:
        if mask & ~(units[nodes[parent]] & units[nodes[child]]):
            raise ValueError("Native mapping edge has an inconsistent target mask")
        outgoing[parent].append((child, mask))
        result += _u32(parent) + _u32(child) + _enum(kind, (0, 1)) + _text(alias) + _mask(mask)
    result += _bounded_count(input_table, 1024)
    for owner, kind, path, digest, mask in input_table:
        if mask & ~units[nodes[owner]]:
            raise ValueError("Native mapping input has an inconsistent target mask")
        result += (
            _u32(owner) + _enum(kind, (0, 1)) + _text(portable_path(path))
            + _digest(digest) + _mask(mask)
        )
    for position in range(len(TARGETS)):
        bit = 1 << position
        pending, visited = [index[root]], set()
        while pending:
            unit = pending.pop()
            if unit not in visited:
                visited.add(unit)
                pending.extend(child for child, mask in outgoing[unit] if mask & bit)
        if visited != {index[node] for node, mask in units.items() if mask & bit}:
            raise ValueError("Unreachable unit in a native mapping target graph")
    if len(result) > 65_536:
        raise ValueError(f"Native mapping manifest exceeds 65536 bytes ({len(result)})")
    return bytes(result)


def _node_at(nodes, position):
    if type(position) is not int or not 0 <= position < len(nodes):
        raise ValueError("Native mapping graph has an invalid unit index")
    return nodes[position]


def combine(observations):
    """Merge the independently observed release closures and encode each mapper."""
    by_target = {data["destination"]: data for data in observations}
    if len(observations) != len(TARGETS) or set(by_target) != set(TARGETS):
        raise ValueError("Native mapping input must contain each supported target exactly once")
    first = by_target[TARGETS[0]]
    mapping_names = set(first["mappings"])
    rust, settings = first["rust"], first["settings"]
    if not mapping_names:
        raise ValueError("Native mapping input does not contain any mappings")
    manifests = {}
    for mapping in sorted(mapping_names):
        roots, units, edges, inputs = set(), {}, {}, {}
        for position, target in enumerate(TARGETS):
            data = by_target[target]
            if data["rust"] != rust or data["settings"] != settings or set(data["mappings"]) != mapping_names:
                raise ValueError("Native mapping target observations disagree on the build contract")
            unit_mask = 1 << position
            graph = data["mappings"][mapping]
            nodes = list(map(_unit_key, graph["units"]))
            if len(nodes) != len(set(nodes)):
                raise ValueError("Duplicate native mapping unit")
            roots.add(_node_at(nodes, graph["root"]))
            for node in nodes:
                units[node] = units.get(node, 0) | unit_mask
            for parent, child, kind, alias in graph["edges"]:
                key = _node_at(nodes, parent), _node_at(nodes, child), kind, alias
                if edges.get(key, 0) & unit_mask:
                    raise ValueError("Duplicate native mapping edge")
                edges[key] = edges.get(key, 0) | unit_mask
            for owner, kind, path, digest in graph["inputs"]:
                key = _node_at(nodes, owner), kind, path, digest
                if inputs.get(key, 0) & unit_mask:
                    raise ValueError("Duplicate native mapping input")
                inputs[key] = inputs.get(key, 0) | unit_mask
        if len(roots) != 1:
            raise ValueError(f"Native mapping root differs across release targets: {mapping}")
        manifests[mapping] = encode(rust, settings, roots.pop(), units, edges, inputs)
    return manifests
