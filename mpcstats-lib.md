# MPCStats Library

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

## Run
```bash
python main.py
```

## Implementation
Statistics operations implementation is in [mpcstats_lib.py](./mpcstats_lib.py).
