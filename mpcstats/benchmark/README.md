# MPCStats Benchmarking

## Preparation

### Protocols definitions
First specify which protocols to use for benchmarking in:
`./protocols.py`

For each protocol used, the associated `.x` file needs to be built. To do this, run `./gen_vms.py`

### Datasets for benchmarking
Next create the datasets to be used for benchmarking in `./datasets`.
The datasets should be in CSV format without a header line.
datasets whose names start with '_' are ignored.

#### Dataset generation script
You can use `./gen_dataset.py` to randomly generate datasets for benchmarking purposes.

### Computation defintions
Lastly, define the computations to be benchmarked in `./computation_defs/templates`.

By executing `./gen_comp_defs.py`, computaion definition instances for all dataset and template combinations will be created in the `./computations_defs` directory.

Computation definitions whose names start with '_' are ignored.

### Setting up ssl
On party 0 host, in `mpcstats/benchmark` directory, run:

```
../../Scripts/setup-ssl.sh 3
```

Then, copy `Player-Data/P{0,1,2}.{pem,key}` to the other party hosts as explained below.

```
The certificates should be the same on every host. Also make sure that it's still valid. Certificates generated with `Scripts/setup-ssl.sh` expire after a month.
```

```bash
scp pse-eu:'MP-SPDZ/mpcstats/benchmark/Player-Data/*.pem' .
scp pse-eu:'MP-SPDZ/mpcstats/benchmark/Player-Data/*.key' .
scp *.pem pse-us:MP-SPDZ/mpcstats/benchmark/Player-Data
scp *.key pse-us:MP-SPDZ/mpcstats/benchmark/Player-Data
scp *.pem pse-asia:MP-SPDZ/mpcstats/benchmark/Player-Data
scp *.key pse-asia:MP-SPDZ/mpcstats/benchmark/Player-Data
```

Fianlly, call `c_rehash` on the machines to which the pem/key files are copied

```
c_rehash MP-SPDZ/mpcstats/benchmark/Player-Data
```


## Running the benchmark
Execute the `./driver.py [scenario ID]` to run the benchmarks and output the results as a CSV to stdout.

To get the list of secnario IDs, run:

```
./driver.sh -h
```

### Setting up a remote machine
Assuming a Ubuntu 24.04, x86, 64-bit instance

- Install necessary libraries
```
sudo apt update
sudo apt-get install -y automake build-essential clang cmake git libboost-all-dev libgmp-dev libntl-dev libsodium-dev libssl-dev libtool python3
```

- Install MP-SPDZ
```
git clone https://github.com/exfinen/MP-SPDZ.git
cd MP-SPDZ
git checkout benchmarker
```

- Copy `*.so` files
Copy `MP-SPDZ/libFHE.so` amd `MPSPDZ/libSPDZ.so` to the new remote machine

- Copy `*.x` files
Copy `MP-SPDZ/*.x` to the new remote machine

- Add `*.so` files to the library search path
Add `export LD_LIBRARY_PATH=<MP-SPDZ directory>` to `.bashrc` or a similar configuration file

### Preparing HOSTS file
Create `MP-SPDZ/HOSTS` of the following contents:

```
<Party 0 IP>
<Party 1 IP>
<Party 2 IP>
...
```

Also make sure that you use correct party number on each party machine.

For example, if you use party number 1 on party-2 machine, MPC will not function. Each party has an assigned port number that is the base port number + party number.

In such a case, if the base port number is the default 5000, party 2 will try to connect to itself using port 5001, but the vm is listening to port 5002 on part-2 machine.
