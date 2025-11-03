#!/usr/bin/env python3
import os
import sys
import subprocess
from pathlib import Path


def main():
    if len(sys.argv) < 2:
        print(
            "Usage: python run_parties.py <input_dir> [protocol] [program] [--port PORT]"
        )
        print("  --port PORT: Base port number (default: 5001)")
        sys.exit(1)

    input_dir = Path(sys.argv[1])
    protocol = sys.argv[2] if len(sys.argv) > 3 else "mascot"
    program = sys.argv[3] if len(sys.argv) > 3 else "tutorial"

    # Parse port option, default to 5001
    port_base = 5001
    for idx, arg in enumerate(sys.argv):
        if arg == "--port" and idx + 1 < len(sys.argv):
            try:
                port_base = int(sys.argv[idx + 1])
            except ValueError:
                print(f"Error: --port requires a valid port number")
                sys.exit(1)
            break

    if not input_dir.is_dir():
        print(f"Error: {input_dir} is not a valid directory")
        sys.exit(1)

    # Get sorted list of files
    files = sorted(f for f in input_dir.iterdir() if f.is_file())
    num_parties = len(files)

    if num_parties < 1:
        print(f"No input files found in {input_dir}")
        sys.exit(1)

    session = f"{protocol}_{program}_{os.getpid()}"

    # Get the absolute path to MP-SPDZ directory (where libSPDZ.so is located)
    # The script is in MP-SPDZ/, so __file__'s parent is the SPDZ root
    spdz_root = Path(__file__).parent.resolve()

    # Set library path for macOS (DYLD_LIBRARY_PATH) and Linux (LD_LIBRARY_PATH)
    env = os.environ.copy()
    current_dyld = env.get("DYLD_LIBRARY_PATH", "")
    current_ld = env.get("LD_LIBRARY_PATH", "")
    env["DYLD_LIBRARY_PATH"] = (
        f"{spdz_root}:{current_dyld}" if current_dyld else str(spdz_root)
    )
    env["LD_LIBRARY_PATH"] = (
        f"{spdz_root}:{current_ld}" if current_ld else str(spdz_root)
    )

    for i, file in enumerate(files):
        abs_file = file.resolve()
        print(abs_file)
        # Use absolute path to the party executable
        party_exe = spdz_root / f"{protocol}-party.x"
        # Export library paths in the bash command to ensure they're available
        export_cmd = f'export DYLD_LIBRARY_PATH="{spdz_root}:$DYLD_LIBRARY_PATH"; export LD_LIBRARY_PATH="{spdz_root}:$LD_LIBRARY_PATH";'
        cmd = f'{export_cmd} {party_exe} -N {num_parties} -I -p {i} -pn {port_base} {program} < "{abs_file}"'
        print(cmd)

        if i == 0:
            subprocess.run(
                ["tmux", "new-session", "-d", "-s", session, f"bash -c '{cmd}; bash'"],
                env=env,
            )
        else:
            subprocess.run(
                ["tmux", "split-window", "-v", "-t", session, f"bash -c '{cmd}; bash'"],
                env=env,
            )

    subprocess.run(["tmux", "select-layout", "-t", session, "tiled"])
    subprocess.run(["tmux", "attach-session", "-t", session])


if __name__ == "__main__":
    main()
