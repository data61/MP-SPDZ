#!/usr/bin/env python3
import sys, subprocess, threading
from pathlib import Path
import shlex


def main():
    if len(sys.argv) < 2:
        print(
            "Usage: python run_parties.py <input_dir> [protocol] [program] [--port PORT]"
        )
        sys.exit(1)

    input_dir = Path(sys.argv[1])
    protocol = sys.argv[2] if len(sys.argv) > 2 else "shamir" # change to shamir
    program = sys.argv[3] if len(sys.argv) > 3 else "matsat"

    # --port (default 5001)
    port_base = 5001
    if "--port" in sys.argv:
        port_base = int(sys.argv[sys.argv.index("--port") + 1])

    files = sorted(f for f in input_dir.iterdir() if f.is_file())
    num_parties = len(files)
    if num_parties < 1:
        print(f"No input files found in {input_dir}")
        sys.exit(1)

    spdz_root = Path(__file__).parent.resolve()
    party_exe = spdz_root / f"{protocol}-party.x"
    print("running with protocol: ", protocol)

    procs = []
    for i, file in enumerate(files):
        # Build command exactly like the working shell command
        abs_file = file.resolve()
        cmd = (
            f"export DYLD_LIBRARY_PATH={shlex.quote(str(spdz_root))}:$DYLD_LIBRARY_PATH; "
            f"export LD_LIBRARY_PATH={shlex.quote(str(spdz_root))}:$LD_LIBRARY_PATH; "
            f"{shlex.quote(str(party_exe))} -N {num_parties} -I -p {i} -pn {port_base} {shlex.quote(program)} < {shlex.quote(str(abs_file))}"
        )
        print(cmd)
        p = subprocess.Popen(
            ["bash", "-c", cmd],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        procs.append((p, i, file.name))
        print(f"[launch] party {i} ({file.name}) → pid {p.pid}")

    # Read output from all parties concurrently
    def read_output(p, party_id, fname):
        for line in p.stdout:
            print(f"[party {party_id}] {line.rstrip()}")

    threads = []
    for p, i, fname in procs:
        t = threading.Thread(target=read_output, args=(p, i, fname), daemon=True)
        t.start()
        threads.append((t, p, i, fname))

    # Wait for all processes
    for t, p, i, fname in threads:
        rc = p.wait()
        t.join(timeout=1)
        print(f"[done] party {i} ({fname}) exit={rc}")


if __name__ == "__main__":
    main()
