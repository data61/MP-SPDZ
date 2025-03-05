# MPCStats Library

This library allows users to write simple python to calculate stats function using MPC without the need to interact with MP-SPDZ itself. You can see the example in main.py, and all the stats functions implemented in mpcstats_lib.py

## Installation

Clone the repo.

```bash
git clone https://github.com/ZKStats/MP-SPDZ
cd MP-SPDZ
```

Install dependencies.

```bash
make setup
```

Build the MPC vm for `semi` protocol

```bash
make -j8 semi-party.x
# Make sure `semi-party.x` exists
ls semi-party.x
```

If you're on macOS and see the following linker warning, you can safely ignore it:

```bash
ld: warning: search path '/usr/local/opt/openssl/lib' not found
```

## Run Example

```bash
cd mpcstats
python main.py
```

In this example, you can see how each data are easily manipulated using MPCStats function. Most descriptions are already commented in the code.

## Implementation

Statistics operations implementation is in [mpcstats_lib.py](./mpcstats_lib.py). We may add new supported functions in the future or feel free to PR!
