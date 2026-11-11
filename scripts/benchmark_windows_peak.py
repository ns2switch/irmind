#!/usr/bin/env python3
"""Run a benchmark and record its Windows peak working set."""
import subprocess
import sys
import time
from pathlib import Path
from evtx_memory import windows_processes


def main():
    command = sys.argv[1:]
    if not command:
        raise SystemExit('benchmark executable is required')
    name = Path(command[0]).name.lower()
    started = time.monotonic()
    with subprocess.Popen(command) as child:
        peak = 0
        try:
            while child.poll() is None:
                for pid, _, _, working_set in windows_processes((name,)):
                    if pid == child.pid:
                        peak = max(peak, working_set)
                time.sleep(0.02)
        finally:
            if child.poll() is None:
                child.kill()
            child.wait()
        if child.returncode == 0 and peak == 0:
            raise SystemExit('benchmark working set could not be measured')
        print(f'WORKER_SWEEP peak_rss_kib={peak // 1024} elapsed_seconds={time.monotonic() - started:.2f}')
        raise SystemExit(child.returncode)


if __name__ == '__main__':
    main()
