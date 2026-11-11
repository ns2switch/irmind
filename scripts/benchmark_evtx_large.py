#!/usr/bin/env python3
"""Measure the release ingestion host and its actual contained decoder children."""
import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import time
from evtx_memory import processes


def measure(executable, mib, work, batch_files, single=False, dense=False, workers=None):
    initial_free = shutil.disk_usage(work).free
    with tempfile.TemporaryDirectory(prefix='evtx-large-', dir=work) as directory:
        output = Path(directory) / 'result.jsonl'
        error = Path(directory) / 'error.txt'
        with output.open('wb') as stdout, error.open('wb') as stderr:
            command = [str(executable), str(mib), '--batch-files', str(batch_files)]
            if workers is not None: command.extend(['--workers', str(workers)])
            if single: command.append('--single-source')
            if dense: command.append('--dense-source')
            process = subprocess.Popen(command, cwd=directory, stdout=stdout, stderr=stderr)
        peaks = {'parent': 0, 'helper': 0}
        child_peaks = {}
        deadline = time.monotonic() + 3600
        try:
            while process.poll() is None:
                for pid, parent, name, peak in processes():
                    if pid == process.pid:
                        peaks['parent'] = max(peaks['parent'], peak)
                    elif parent == process.pid and name.lower().startswith('irmind-evtx'):
                        peaks['helper'] = max(peaks['helper'], peak)
                        child_peaks[pid] = max(child_peaks.get(pid, 0), peak)
                if time.monotonic() >= deadline:
                    process.kill()
                    raise TimeoutError('benchmark collection deadline exceeded')
                time.sleep(0.02)
            results = [json.loads(line) for line in output.read_text().splitlines()]
            if process.returncode:
                result = {'phase': 'failed', 'profile': 'release', 'exit_code': process.returncode,
                          'error': error.read_text()[:4096], 'last_progress': results[-1] if results else None}
            else:
                result = next(row for row in results if row.get('phase') == 'complete')
            if process.returncode == 0 and not all(peaks.values()):
                raise RuntimeError('benchmark memory could not be measured for both processes')
            result.update({'corpus_mib': mib, 'single_source': single, 'dense_source': dense, 'parent_peak_bytes': peaks['parent'],
                           'helper_peak_bytes': peaks['helper'], 'observed_children': len(child_peaks),
                           'memory_method': ('20 ms sampling of resident bytes via ps; sampled peak, not a high-water counter' if platform.system() == 'Darwin' else '20 ms sampling of OS process high-water resident/working-set counters; per-process maximum, not sum'),
                           'requested_workers': workers, 'available_cores': os.cpu_count(),
                           'initial_free_disk_bytes': initial_free, 'os': platform.system(), 'architecture': platform.machine()})
            return result
        finally:
            if process.poll() is None:
                process.kill()
            process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('executable', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--smoke', action='store_true')
    parser.add_argument('--extended', action='store_true')
    parser.add_argument('--worker-sweep', action='store_true', help='Measure a single 1 GiB source at one, four, all and automatic workers')
    parser.add_argument('--batch-files', type=int, choices=(1, 4), default=int(os.environ.get('EVTX_BATCH_FILES', '4')))
    args = parser.parse_args()
    if args.batch_files not in (1, 4):
        parser.error('batch-files must be 1 or 4')
    executable = args.executable.resolve(strict=True)
    results = []
    corpora = [(16, False, False)] if args.smoke else [(100, False, False), (1024, False, False)]
    if args.extended:
        corpora.append((1024, True, False))
        if platform.system() == 'Linux': corpora.append((4096, True, False))
        corpora.extend([(100, True, True), (1024, True, True), (4096, True, True)])
    settings = [(mib, single, dense, None) for mib, single, dense in corpora]
    if args.worker_sweep:
        caps = list(dict.fromkeys([1, 4, min(os.cpu_count() or 1, 256), None]))
        settings = [(1024, True, False, cap) for cap in caps]
    for mib, single, dense, workers in settings:
        result = measure(executable, mib, Path.cwd(), args.batch_files, single, dense, workers)
        print(json.dumps(result, sort_keys=True), flush=True)
        results.append(result)
        args.output.write_text(json.dumps({'results': results}, indent=2) + '\n')
        if result['phase'] == 'failed':
            raise SystemExit('EVTX benchmark failed; inspect the attached bounded diagnostic result')


if __name__ == '__main__':
    main()
