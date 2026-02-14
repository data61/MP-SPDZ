#  MP-SPDZ Test Suite

Welcome to the MP-SPDZ test suite! This guide will get you running tests in no time.

##  Prerequisites

Use **[uv](https://github.com/astral-sh/uv)** for fast Python package management.

### Install uv
Run this one-liner to install `uv`:
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

## 🏃‍♂️ Running Tests

**IMPORTANT:** Always run tests from the **project root directory** (`MP-SPDZ/`), not from inside the `tests/` folder.

### 1. Run All Tests
```bash
uv run pytest
```

### 2. Run Specific Tests
To run the MatSat clause weights tests with verbose output (recommended):
```bash
uv run pytest tests/test_matsat_clause_weights.py -v -s
```

### 3. Run a Single Test Case
Target a specific test method:
```bash
uv run pytest tests/test_matsat_clause_weights.py::TestMatSatClauseWeights::test_conflict_resolution -v -s
```

## 🛠️ Troubleshooting

- **SSL Keys Missing**: If tests fail with "Cannot access Player-Data/P0.pem", run the SSL setup script:
  ```bash
  ./Scripts/setup-ssl.sh <number_of_parties>
  # Example for 6 parties:
  ./Scripts/setup-ssl.sh 6
  ```
- **Stale Processes**: If tests hang, kill leftover party processes:
  ```bash
  pkill -f shamir-party.x
  ```

Happy Testing! 🎉
