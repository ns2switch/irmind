"""Normalize a shipping Cargo build's observed inputs and compiler edges."""
from collections import defaultdict
from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import re
import subprocess

from .codec import portable_path

MANIFEST_NAME = "native-mapping-manifest.bin"
RUNTIME_RECIPE = {
    "build": "cargo build --release --locked -p irmind",
    "codegen": "release",
    "debug_assertions": False,
    "overflow_checks": False,
    "panic": "unwind",
}


def canonical_json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False, separators=(",", ":")).encode("utf-8")


def digest(data):
    return sha256(data).hexdigest()


def compiler_fields(path):
    buffer = memoryview(path.read_bytes())
    fields = []
    while buffer:
        if len(buffer) < 4:
            raise ValueError("Short compiler observation")
        length = int.from_bytes(buffer[:4], "big")
        if length > len(buffer) - 4:
            raise ValueError("Truncated compiler observation field")
        fields.append(bytes(buffer[4:4 + length]).decode("utf-8"))
        buffer = buffer[4 + length:]
    if len(fields) < 5:
        raise ValueError("Missing compiler observation fields")
    return fields


def options(arguments, key):
    prefix = key + "="
    for index, item in enumerate(arguments):
        if item == key:
            yield arguments[index + 1]
        elif item.startswith(prefix):
            yield item[len(prefix):]


def single(arguments, key):
    values = list(options(arguments, key))
    if len(values) != 1:
        raise ValueError(f"Expected one compiler option {key}")
    return values[0]


@dataclass
class Invocation:
    package_dir: Path
    package_name: str
    version: str
    generated: Path | None
    name: str
    crate_type: str
    output: Path
    extra: str
    features: list
    cfg: list
    externs: dict
    args: list

    @classmethod
    def read(cls, path):
        package_dir, name, version, generated, *args = compiler_fields(path)
        cfg = sorted(set(options(args, "--cfg")))
        feature_flags = [flag for flag in cfg if flag.startswith("feature=")]
        extra = [option.partition("=")[2] for option in options(args, "-C")
                 if option.startswith("extra-filename=")]
        if len(extra) > 1:
            raise ValueError("Compiler invocation has two output suffixes")
        externs = {}
        for value in options(args, "--extern"):
            alias, separator, artifact = value.partition("=")
            if not separator:
                if alias == "proc_macro":
                    continue
                raise ValueError("Unknown compiler builtin dependency")
            if alias in externs:
                raise ValueError("Duplicate Rust dependency alias")
            externs[alias] = Path(artifact).resolve()
        return cls(
            Path(package_dir).resolve(), name, version, Path(generated).resolve() if generated else None,
            single(args, "--crate-name"), single(args, "--crate-type"),
            Path(single(args, "--out-dir")).resolve(), extra[0] if extra else "",
            sorted(json.loads(flag.partition("=")[2]) for flag in feature_flags),
            sorted(set(cfg) - set(feature_flags)), externs, args,
        )

    @property
    def is_script(self):
        return self.name == "build_script_build" and self.crate_type == "bin"

    def output_paths(self):
        for prefix, ext in (("lib", ".rlib"), ("lib", ".rmeta"), ("lib", ".so"),
                            ("lib", ".dylib"), ("", ".dll")):
            candidate = self.output / f"{prefix}{self.name}{self.extra}{ext}"
            if candidate.is_file():
                yield candidate.resolve()


def cargo_metadata(source, env):
    result = subprocess.run(
        ["cargo", "metadata", "--locked", "--format-version=1"], env=env, cwd=source,
        stdout=subprocess.PIPE, text=True, check=True,
    )
    return {Path(package["manifest_path"]).resolve().parent: package
            for package in json.loads(result.stdout)["packages"]}


def committed_files(source, checkout, revision):
    tree = subprocess.check_output(["git", "ls-tree", "-r", "-z", revision], cwd=checkout)
    files = set()
    for field in tree.split(b"\0"):
        if not field:
            continue
        descriptor, name = field.split(b"\t", 1)
        if descriptor.startswith((b"100644 blob ", b"100755 blob ")):
            files.add(source / portable_path(name.decode("utf-8")))
    return files


def quoted_split(value):
    # rustc's make-style dep-info escapes spaces and hashes, but uses literal
    # path separators on Windows. The first line contains all dependencies.
    return [re.sub(r"\\([ #\\])", r"\1", part)
            for part in re.findall(r"(?:\\[ #\\]|[^\s])+", value)]


def normalized_inputs(unit, source, committed):
    path = unit.output / f"{unit.name}{unit.extra}.d"
    lines = path.read_text(encoding="utf-8").splitlines()
    _, delimiter, dependencies = lines[0].partition(": ")
    if not delimiter:
        raise ValueError("Compiler did not produce complete dependency information")
    inputs, environment = {}, {}
    # First-party source paths in Cargo invocations are relative to the
    # workspace; registry sources are absolute or relative to the package.
    for item in quoted_split(dependencies):
        original = Path(item)
        candidates = [original] if original.is_absolute() else [source / original, unit.package_dir / original]
        actual = next((candidate.resolve() for candidate in candidates if candidate.is_file()), None)
        if actual is None:
            raise ValueError("Compiler input file could not be resolved")
        if unit.generated is not None and actual.is_relative_to(unit.generated):
            logical = actual.relative_to(unit.generated).as_posix()
            if logical != MANIFEST_NAME:
                inputs[(1, "outputs/" + portable_path(logical))] = digest(actual.read_bytes())
        elif actual.is_relative_to(source):
            logical = portable_path(actual.relative_to(source).as_posix())
            if actual not in committed:
                raise ValueError("A reachable mapping input is outside the committed release tree")
            inputs[(0, logical)] = digest(actual.read_bytes())
        elif not actual.is_relative_to(unit.package_dir):
            raise ValueError("A reachable mapping input is outside its package")
    for line in lines:
        if not line.startswith("# env-dep:"):
            continue
        name, _, value = line.removeprefix("# env-dep:").partition("=")
        if name in ("OUT_DIR", "CARGO_MANIFEST_DIR"):
            continue
        if not name.startswith(("CARGO_PKG_", "CARGO_CRATE_")):
            raise ValueError(f"Unclassified compile-time environment input {name}")
        environment[name] = value
    return inputs, environment


def source_descriptor(package, lock_entries, source):
    lock_source = package["source"]
    if lock_source is None:
        path = Path(package["manifest_path"]).resolve().parent
        if not path.is_relative_to(source):
            raise ValueError("Out-of-tree path dependency in native mapping closure")
        return 0, portable_path(path.relative_to(source).as_posix()), "0" * 64
    entry = lock_entries[(package["name"], package["version"], lock_source)]
    if lock_source.startswith("registry+"):
        return 1, lock_source.removeprefix("registry+"), entry["checksum"]
    if lock_source.startswith("git+"):
        uri = lock_source.removeprefix("git+")
        url, sep, revision = uri.partition("#")
        if not sep:
            raise ValueError("Unlocked Git dependency in native mapping closure")
        return 2, url.split("?", 1)[0] + "#" + revision, digest(revision.encode("utf-8"))
    raise ValueError("Unclassified dependency source in native mapping closure")


def build_edges(units):
    by_artifact, scripts = {}, defaultdict(list)
    for index, unit in enumerate(units):
        for artifact in unit.output_paths():
            if artifact in by_artifact:
                raise ValueError("Compiler artifacts have ambiguous producers")
            by_artifact[artifact] = index
        if unit.is_script:
            scripts[unit.package_dir, tuple(unit.features)].append(index)
    edge_map = {}

    def resolve(index):
        if index not in edge_map:
            unit = units[index]
            edges = [(by_artifact[path], int(unit.is_script), alias)
                     for alias, path in unit.externs.items()]
            if unit.generated is not None and not unit.is_script:
                candidates = scripts[unit.package_dir, tuple(unit.features)]
                if len(candidates) != 1:
                    # Cargo can use a host and a target instance of the same
                    # package with identical features. Their build-script
                    # compilations must agree on their input edges.
                    signatures = {
                        tuple(sorted(units[item].externs.items())) for item in candidates
                    }
                    if len(signatures) != 1:
                        raise ValueError(f"Ambiguous build-script input for {unit.package_name}")
                edges.append((candidates[0], 1, "build_script_build"))
            edge_map[index] = edges
        return edge_map[index]

    return resolve


def observe_closure(root, units, edges, packages, lock_entries, source, committed):
    node_data, input_data, outgoing = {}, {}, set()
    visited = set()
    remaining = [(root, 0)]
    while remaining:
        index, context = remaining.pop()
        unit = units[index]
        if unit.is_script:
            context = 2
        elif unit.crate_type == "proc-macro":
            context = 1
        key = index, context
        if key in visited:
            continue
        visited.add(key)
        package = packages[unit.package_dir]
        origin = source_descriptor(package, lock_entries, source)
        if package["name"] != unit.package_name or package["version"] != unit.version:
            raise ValueError("Compiler and locked Cargo package metadata disagree")
        files, compile_env = normalized_inputs(unit, source, committed)
        effective = {
            "edition": single(unit.args, "--edition"),
            "rust_version": package["rust_version"],
            "links": package["links"],
            "crate_type": unit.crate_type,
            "cfg": unit.cfg,
            "semantic_codegen": sorted(
                option for option in options(unit.args, "-C")
                if option.partition("=")[0] in {
                    "panic", "debug-assertions", "overflow-checks", "target-feature", "target-cpu",
                }
            ),
            "compile_env": compile_env,
        }
        # Input paths observed by rustc include source, data and generated
        # code. Registry payloads are separately bound to the lock checksum.
        node_data[key] = (unit.package_name, unit.version, *origin, context, tuple(unit.features),
                          digest(canonical_json(effective)))
        input_data[key] = files
        for child, kind, alias in edges(index):
            dep = units[child]
            child_context = 2 if dep.is_script else int(context != 0 or dep.crate_type == "proc-macro")
            outgoing.add((key, (child, child_context), kind, alias))
            remaining.append((child, child_context))
    # Two distinct Cargo artifacts can resolve to identical normalized inputs.
    # If so, merge them only when they also have identical outgoing edges and
    # the same semantic input commitments.
    definitions = {}
    for key, node in node_data.items():
        footprint = (
            sorted(input_data[key].items()),
            sorted((node_data[to], kind, alias) for parent, to, kind, alias in outgoing if parent == key),
        )
        if definitions.setdefault(node, footprint) != footprint:
            raise ValueError("Ambiguous normalized native mapping unit")
    ordered = sorted(definitions)
    indexes = {node: index for index, node in enumerate(ordered)}
    return {
        "root": indexes[node_data[(root, 0)]],
        "units": ordered,
        "edges": sorted({(indexes[node_data[a]], indexes[node_data[b]], kind, alias)
                         for a, b, kind, alias in outgoing}),
        "inputs": sorted({(indexes[node_data[owner]], kind, path, content)
                           for owner, files in input_data.items() for (kind, path), content in files.items()}),
    }


def normalize(records, packages, checkout, revision, source, destination, env):
    import tomllib

    units = [Invocation.read(path) for path in sorted(records.glob("*.bin"))]
    candidates = [
        i for i, unit in enumerate(units)
        if unit.package_name.startswith("irmind-mod-mapping-") and unit.crate_type == "lib"
        and unit.generated is not None and (unit.generated / MANIFEST_NAME).is_file()
    ]
    if not candidates:
        raise ValueError("No production native mapping invocations were recorded")
    roots = {units[index].package_name: index for index in candidates}
    if len(roots) != len(candidates):
        raise ValueError("Native mapping root was built more than once")
    files = committed_files(source, checkout, revision)
    with (source / "Cargo.lock").open("rb") as stream:
        locked = {(part["name"], part["version"], part.get("source")): part
                  for part in tomllib.load(stream)["package"]}
    rust = subprocess.check_output(["rustc", "--version"], cwd=source, env=env, text=True).split()[1]
    resolver = build_edges(units)
    return {
        "destination": destination,
        "rust": rust,
        "settings": digest(canonical_json(RUNTIME_RECIPE)),
        "mappings": {
            name: observe_closure(index, units, resolver, packages, locked, source, files)
            for name, index in sorted(roots.items())
        },
    }
