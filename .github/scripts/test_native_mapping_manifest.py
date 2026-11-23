"""Check the production V2 writer against the independently specified bytes."""
from copy import deepcopy
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import unittest

from native_mapping.codec import TARGETS, combine

ROOT = Path(__file__).resolve().parents[2]
VECTOR = ROOT / "docs/development/vectors/native-mapping-manifest-v2.py"
SPEC = importlib.util.spec_from_file_location("native_mapping_vector", VECTOR)
REFERENCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REFERENCE)


def observations(sample):
    names = {unit[0]: n for n, unit in enumerate(sample["units"])}
    graph = {
        "root": names["mapping-example"],
        "units": [list(unit[:4]) + [unit[4].hex(), unit[5], list(unit[6]), unit[7].hex()]
                  for unit in sample["units"]],
        "edges": [(names[owner], names[dep], kind, alias)
                  for owner, dep, kind, alias in sample["edges"]],
        "inputs": [(names[owner], kind, path, sha256(body.encode()).hexdigest())
                   for owner, kind, path, body in sample["inputs"]],
    }
    return [{"destination": target, "rust": sample["rust"],
             "settings": sha256(sample["settings"].encode()).hexdigest(),
             "mappings": {"mapping-example": deepcopy(graph)}} for target in TARGETS]


class ManifestV2(unittest.TestCase):
    def test_production_writer_matches_golden(self):
        vector = json.loads(VECTOR.with_suffix(".json").read_text())
        self.assertEqual(REFERENCE.vectors(), vector)
        graph = observations(REFERENCE.BASE)
        result = combine(graph)["mapping-example"]
        self.assertEqual(result, bytes.fromhex(vector["canonical_hex"]))
        self.assertEqual(sha256(result).hexdigest(), vector["sha256"])
        self.assertEqual(combine(list(reversed(graph))), combine(graph))

    def test_invalid_or_ambiguous_graphs_fail_closed(self):
        root = "mapping-example"
        graph = observations(REFERENCE.BASE)
        incomplete = graph[:-1]
        changed_root = deepcopy(graph)
        changed_root[2]["mappings"][root]["units"][0][6] = ["changed"]
        disconnected = deepcopy(graph)
        disconnected[2]["mappings"][root]["edges"].pop()
        invalid_path = deepcopy(graph)
        invalid_path[1]["mappings"][root]["inputs"][0] = (0, 0, "../data", "0" * 64)
        for case in (incomplete, changed_root, disconnected, invalid_path):
            with self.assertRaises(ValueError):
                combine(case)

    def test_local_inputs_and_actual_compiler_configuration_are_committed(self):
        base = combine(observations(REFERENCE.BASE))
        for position, field, replacement in [
            (0, 7, "a" * 64),  # effective manifest
            (1, 1, "2.0.1"),  # reachable version
            (1, 4, "c" * 64),  # reachable lock checksum
            (1, 6, ["additional", "numeric"]),  # actual production feature
        ]:
            data = observations(REFERENCE.BASE)
            data[0]["mappings"]["mapping-example"]["units"][position][field] = replacement
            if position == 0:
                for item in data[1:]:
                    item["mappings"]["mapping-example"]["units"][position][field] = replacement
            self.assertNotEqual(combine(data), base)

    def test_platform_specific_dependencies_do_not_change_the_root(self):
        equivalent = observations(REFERENCE.BASE)
        disjoint = deepcopy(equivalent)
        disjoint[-1]["mappings"]["mapping-example"]["inputs"][2] = (2, 0, "src/lib.rs", "0" * 64)
        wire = combine(disjoint)
        self.assertNotEqual(wire, combine(equivalent))
        self.assertEqual(wire, combine(list(reversed(disjoint))))


if __name__ == "__main__":
    unittest.main()
