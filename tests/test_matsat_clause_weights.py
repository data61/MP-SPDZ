"""
Tests for solve_matsat with varying clause weights.

This module tests the MatSat solver with different clause weight configurations
for 2-3 party scenarios where each party provides one clause.

Run with: uv run pytest tests/test_matsat_clause_weights.py -v -s
"""

import pytest
import subprocess
import tempfile
import sys
from pathlib import Path

# Add the MP-SPDZ directory to the path
mp_spdz_root = Path(__file__).parent.parent
sys.path.insert(0, str(mp_spdz_root))


def compile_and_run_mpc(test_name, clauses, n, m, weights, description):
    """
    Compile and run an MPC program for a specific test case.
    
    Args:
        test_name: Name for the test program
        clauses: List of clauses for the SAT formula
        n: Number of variables
        m: Number of clauses
        weights: List of clause weights
        description: Human-readable description of the test
        
    Returns:
        Tuple of (is_solved, satisfied_clauses) from the MPC execution
    """

    # Generate formula description dynamically
    formula_parts = []
    for i, clause in enumerate(clauses):
        literals = []
        for lit in clause:
            if lit > 0:
                literals.append(f"x{lit}")
            else:
                literals.append(f"NOT x{abs(lit)}")
        clause_str = "(" + " OR ".join(literals) + ")"
        formula_parts.append(f"{clause_str} [w={weights[i]}]")
    formula_str = " AND ".join(formula_parts)

    mpc_content = f'''"""
{description}
"""
from Compiler.types import sint, sfix, Matrix
from Compiler.library import print_ln, for_range
from Programs.Source.matsat_utils import MatSatUtils

def create_q_matrix(clauses, n, m):
    Q = Matrix(m, 2 * n, sfix)
    
    @for_range(m)
    def _(i):
        @for_range(2 * n)
        def __(j):
            Q[i][j] = sfix(0)
    
    for i, clause in enumerate(clauses):
        for literal in clause:
            if literal > 0:
                Q[i][literal - 1] = sfix(1)
            else:
                Q[i][n + abs(literal) - 1] = sfix(1)
    
    return Q

def create_weight_vector(m, weights):
    w = Matrix(m, 1, sfix)
    for i in range(m):
        w[i][0] = sfix(weights[i])
    return w

# Test parameters
n = {n}
m = {m}
clauses = {clauses}
weights = {weights}

print_ln("=" * 60)
print_ln("{description}")
print_ln("Formula by Input Vector: %s", "{formula_str}")
print_ln("=" * 60)

Q = create_q_matrix(clauses, n, m)
active = create_weight_vector(m, weights)

u_tilde, u, is_solved, satisfied_clauses = MatSatUtils.solve_matsat(
    Q=Q, n=n, m=m, active=active, l=2.0, max_try=5, max_itr=5, weighted=True, print_results=True
)

print_ln("Test completed successfully")
'''
    
    # Write the MPC program to a temporary file
    mpc_file = mp_spdz_root / "Programs" / "Source" / f"{test_name}.mpc"
    with open(mpc_file, 'w') as f:
        f.write(mpc_content)
    
    try:
        # Compile the MPC program
        print(f"\n  Compiling {test_name}...")
        compile_result = subprocess.run(
            ["python3", "compile.py", test_name],
            cwd=mp_spdz_root,
            capture_output=True,
            text=True,
            timeout=60
        )
        
        if compile_result.returncode != 0:
            print(f"  Compilation failed:")
            print(compile_result.stderr)
            pytest.fail(f"Failed to compile {test_name}")
        
        print(f"  Compilation successful")
        
        # Use a unique port for this test to avoid conflicts
        import random
        import time
        
        # Kill any leftover processes from previous runs
        subprocess.run(["pkill", "-f", f"shamir-party.x.*{test_name}"], capture_output=True)
        time.sleep(0.5)  # Give processes time to die
        
        # Run the MPC program with m parties (one per clause)
        print(f"  Running {test_name} with {m} parties...")
        
        # Start all m parties in the background
        parties = []
        for party_id in range(m):
            party_process = subprocess.Popen(
                ["./shamir-party.x", "-N", str(m), "-p", str(party_id), "-h", "localhost", test_name],
                cwd=mp_spdz_root,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            parties.append(party_process)
            time.sleep(0.1)  # Small delay between starting parties
        
        # Wait for all parties to complete
        outputs = []
        errors = []
        for i, party in enumerate(parties):
            stdout, stderr = party.communicate()
            outputs.append(stdout)
            errors.append(stderr)
        
        # Check if any party failed
        failed = False
        for i, party in enumerate(parties):
            if party.returncode != 0:
                print(f"  Party {i} failed with return code {party.returncode}\"")
                print(f"  Party {i} stderr: {errors[i]}")
                failed = True
        
        if failed:
            pytest.fail(f"Failed to run {test_name}")
        
        # Print the output from party 0 (they should all have the same output)
        print(f"  Output from party 0:")
        for line in outputs[0].split('\n'):
            if line.strip():
                print(f"    {line}")
        
        # Parse the output to extract is_solved, satisfied_clauses and u
        output = outputs[0]
        is_solved = None
        satisfied = None
        assignment = {}
        
        for line in output.split('\n'):
            if 'is_solved' in line:
                # Extract the value after 'is_solved ='
                parts = line.split('=')
                if len(parts) > 1:
                    is_solved = int(parts[-1].strip())
            if 'satisfied clauses' in line:
                parts = line.split('=')
                if len(parts) > 1:
                    try:
                        satisfied = float(parts[-1].strip())
                    except ValueError:
                        pass
            if 'u[' in line and ']' in line and '=' in line:
                # Parse u[i] = val
                try:
                    left, right = line.split('=')
                    idx = int(left.split('[')[1].split(']')[0])
                    val = int(right.strip())
                    assignment[idx] = val
                except (ValueError, IndexError):
                    pass
        
        # Convert assignment dict to list if we have all values
        u_vector = []
        if assignment:
            for i in range(n):
                u_vector.append(assignment.get(i, 0))
        
        return is_solved, satisfied, u_vector
        
    finally:
        # Clean up the temporary MPC file
        if mpc_file.exists():
            mpc_file.unlink()


class TestMatSatClauseWeights:
    """Test suite for MatSat with varying clause weights."""

    # ========== 2-Party Tests (2 clauses) ==========

    def test_2p_sat_1(self):
        """Test 2-party SAT with uniform weights."""
        is_solved, satisfied, _ = compile_and_run_mpc(
            test_name="test_2p_sat_uniform",
            clauses=[[1], [2]],
            n=2,
            m=2,
            weights=[0.1, 0.9],
            description="2-party SAT: (x1) AND (x2), weights=[0.1, 0.9]"
        )
        assert is_solved == 1, "Should be SAT"
        print(f"  ✓ Test completed: is_solved={is_solved}, satisfied={satisfied}")

    def test_2p_sat_2(self):
        """Test 2-party SAT with heavily biased weights."""
        is_solved, satisfied, _ = compile_and_run_mpc(
            test_name="test_2p_sat_biased",
            clauses=[[1], [2]],
            n=2,
            m=2,
            weights=[0.9, 0.1],
            description="2-party SAT: (x1) AND (x2), weights=[0.9, 0.1]"
        )
        assert is_solved == 1, "Should be SAT"
        print(f"  ✓ Test completed: is_solved={is_solved}, satisfied={satisfied}")

    def test_2p_unsat_1(self):
        """Test 2-party UNSAT with uniform weights."""
        is_solved, satisfied, _ = compile_and_run_mpc(
            test_name="test_2p_unsat_uniform",
            clauses=[[1], [-1]],
            n=1,
            m=2,
            weights=[0.1, 0.9],
            description="2-party UNSAT: (NOT x1) AND (NOT x2), weights=[0.1, 0.9]"
        )
        assert is_solved == 0, "Should be UNSAT"
        print(f"  ✓ Test completed: is_solved={is_solved}, satisfied={satisfied}")

    def test_2p_unsat_2(self):
        """Test 2-party UNSAT with heavily biased weights."""
        is_solved, satisfied, _ = compile_and_run_mpc(
            test_name="test_2p_unsat_biased",
            clauses=[[-1], [-2]],
            n=2,
            m=2,
            weights=[0.9, 0.1],
            description="2-party UNSAT: (NOT x1) AND (NOT x2), weights=[0.9, 0.1]"
        )
        assert is_solved == 0, "Should be UNSAT"
        print(f"  ✓ Test completed: is_solved={is_solved}, satisfied={satisfied}")

    # ========== 3-Party Tests (3 clauses) ==========

    def test_3p_sat_1(self):
        """Test 3-party SAT with uniform weights."""
        is_solved, satisfied, _ = compile_and_run_mpc(
            test_name="test_3p_sat_uniform",
            clauses=[[1], [2], [3]],
            n=3,
            m=3,
            weights=[1/3, 1/3, 1/3],
            description="3-party SAT: (x1) AND (x2) AND (x3), weights=[0.333, 0.333, 0.333]"
        )
        assert is_solved == 1, "Should be SAT"
        print(f"  ✓ Test completed: is_solved={is_solved}, satisfied={satisfied}")

    def test_3party_satisfiable_descending_weights(self):
        """Test 3-party SAT with heavily biased weights."""
        is_solved, satisfied, _ = compile_and_run_mpc(
            test_name="test_3p_sat_biased",
            clauses=[[1], [2], [3]],
            n=3,
            m=3,
            weights=[0.8, 0.15, 0.05],
            description="3-party SAT: (x1) AND (x2) AND (x3), weights=[0.8, 0.15, 0.05]"
        )
        assert is_solved == 1, "Should be SAT"
        print(f"  ✓ Test completed: is_solved={is_solved}, satisfied={satisfied}")

    def test_3p_unsat_1(self):
        """Test 3-party UNSAT with uniform weights."""
        is_solved, satisfied, _ = compile_and_run_mpc(
            test_name="test_3p_unsat_uniform",
            clauses=[[1], [-1], [2]],
            n=2,
            m=3,
            weights=[2, 1, 10],
            description="3-party UNSAT: (x1) AND (NOT x1) AND (x2), weights=[2, 1, 10]"
        )
        assert is_solved == 0, "Should be UNSAT"
        print(f"  ✓ Test completed: is_solved={is_solved}, satisfied={satisfied}")

    def test_3p_unsat_2(self):
        """Test 3-party UNSAT with heavily biased weights."""
        is_solved, satisfied, _ = compile_and_run_mpc(
            test_name="test_3p_unsat_biased",
            clauses=[[1], [-1], [2]],
            n=2,
            m=3,
            weights=[10, 2, 1],
            description="3-party UNSAT: (x1) AND (NOT x1) AND (x2), weights=[10, 2, 1]"
        )
        assert is_solved == 0, "Should be UNSAT"
        print(f"  ✓ Test completed: is_solved={is_solved}, satisfied={satisfied}")


    def test_conflict_resolution(self):
        """
        Test conflict resolution with weights.
        
        Scenario:
        - Variable 0: (x0) weights [100, 1] for clauses [x0, NOT x0] => Expect x0=1
        - Variable 1: (x1) weights [1, 100] for clauses [x1, NOT x1] => Expect x1=0
        - Variable 2: (x2) weights [50, 5] for clauses [x2, NOT x2] => Expect x2=1
        
        The solver should follow the higher weights.
        """
        is_solved, satisfied, assignment = compile_and_run_mpc(
            test_name="test_conflict_resolution",
            clauses=[[1], [-1], [2], [-2], [3], [-3]],
            n=3,
            m=6,
            weights=[100, 1, 1, 100, 50, 5],
            description="Conflict Resolution: Weights prioritize specific assignments"
        )
        
        print(f"  ✓ Assignment received: {assignment}")
        
        # Check basic results
        assert is_solved == 0, "Should be UNSAT"
        assert satisfied == 3, "Should satisfy exactly 3 clauses"
        
        # Check if weights biase the assignment correctly
        assert len(assignment) == 3, "Should have assignments for all 3 variables"
        assert assignment[0] == 1, "x0 should be 1 due to higher weight (100 vs 1) on positive clause"
        assert assignment[1] == 0, "x1 should be 0 due to higher weight (100 vs 1) on negative clause"
        assert assignment[2] == 1, "x2 should be 1 due to higher weight (50 vs 5) on positive clause"
        
        print(f"  ✓ Test completed: Weighted bias confirmed.")


    def test_conflict_resolution_equal_weights(self):
        """
        Test conflict resolution with equal weights for one variable.
        
        Scenario:
        - Variable 0: (x0) weights [100, 1] for clauses [x0, NOT x0] => Expect x0=1
        - Variable 1: (x1) weights [1, 1] for clauses [x1, NOT x1] => Expect x1=0 or x1=1 (Indeterminate but valid)
        - Variable 2: (x2) weights [50, 5] for clauses [x2, NOT x2] => Expect x2=1
        
        The solver should follow the higher weights where present.
        """
        is_solved, satisfied, assignment = compile_and_run_mpc(
            test_name="test_conflict_resolution_equal",
            clauses=[[1], [-1], [2], [-2], [3], [-3]],
            n=3,
            m=6,
            weights=[100, 1, 1, 1, 50, 5],
            description="Conflict Resolution: Equal weights for x1"
        )
        
        print(f"  ✓ Assignment received: {assignment}")
        
        # Check basic results
        assert is_solved == 0, "Should be UNSAT"
        # Satisfied count depends on x1's resolution. 
        # x0=1 (sat clause 0), x2=1 (sat clause 4).
        # x1=0 -> sat clause 3. x1=1 -> sat clause 2.
        # So always 3 satisfied clauses.
        assert satisfied == 3, "Should satisfy exactly 3 clauses"
        
        # Check if weights biase the assignment correctly
        assert len(assignment) == 3, "Should have assignments for all 3 variables"
        assert assignment[0] == 1, "x0 should be 1 due to higher weight (100 vs 1) on positive clause"
        
        # x1 has equal weights (1 vs 1). It should be 0 or 1.
        assert assignment[1] in [0, 1], "x1 should be a valid binary value"
        print(f"  ✓ x1 resolved to {assignment[1]} with equal weights")
        
        assert assignment[2] == 1, "x2 should be 1 due to higher weight (50 vs 5) on positive clause"
        
        print(f"  ✓ Test completed: Weighted bias confirmed.")


    def test_conflict_resolution_stats(self):
        """
        Run conflict resolution with equal weights 50 times to check distribution.
        
        Target Variable: x2 (index 1) - weights 1 vs 1.
        """
        test_name = "test_conflict_resolution_stats"
        clauses = [[1], [-1], [2], [-2], [3], [-3]]
        n = 3
        m = 6
        weights = [100, 1, 1, 1, 50, 5]
        description = "Conflict Resolution Stats: Equal weights for x2 (100 iterations)"
        
        # 1. Generate and Compile (copied from compile_and_run_mpc)
        formula_parts = []
        for i, clause in enumerate(clauses):
            literals = []
            for lit in clause:
                if lit > 0:
                    literals.append(f"x{lit}")
                else:
                    literals.append(f"NOT x{abs(lit)}")
            clause_str = "(" + " OR ".join(literals) + ")"
            formula_parts.append(f"{clause_str} [w={weights[i]}]")
        formula_str = " AND ".join(formula_parts)

        mpc_content = f'''"""
{description}
"""
from Compiler.types import sint, sfix, Matrix
from Compiler.library import print_ln, for_range
from Programs.Source.matsat_utils import MatSatUtils

def create_q_matrix(clauses, n, m):
    Q = Matrix(m, 2 * n, sfix)
    
    @for_range(m)
    def _(i):
        @for_range(2 * n)
        def __(j):
            Q[i][j] = sfix(0)
    
    for i, clause in enumerate(clauses):
        for literal in clause:
            if literal > 0:
                Q[i][literal - 1] = sfix(1)
            else:
                Q[i][n + abs(literal) - 1] = sfix(1)
    
    return Q

def create_weight_vector(m, weights):
    w = Matrix(m, 1, sfix)
    for i in range(m):
        w[i][0] = sfix(weights[i])
    return w

# Test parameters
n = {n}
m = {m}
clauses = {clauses}
weights = {weights}

print_ln("=" * 60)
print_ln("{description}")
print_ln("Formula by Input Vector: %s", "{formula_str}")
print_ln("=" * 60)

Q = create_q_matrix(clauses, n, m)
active = create_weight_vector(m, weights)

u_tilde, u, is_solved, satisfied_clauses = MatSatUtils.solve_matsat(
    Q=Q, n=n, m=m, active=active, l=2.0, max_try=5, max_itr=5, weighted=True, print_results=True
)
print_ln("Test completed successfully")
'''
        mpc_file = mp_spdz_root / "Programs" / "Source" / f"{test_name}.mpc"
        with open(mpc_file, 'w') as f:
            f.write(mpc_content)

        # Compile
        print(f"\n  Compiling {test_name}...")
        subprocess.run(["python3", "compile.py", test_name], cwd=mp_spdz_root, check=True, capture_output=True)
        print("  Compilation successful. Starting 100 iterations...")

        # 2. Run 50 times
        import time
        results = {0: 0, 1: 0} # Track successes
        failures = 0
        
        base_port = 6000 # Use higher base port range
        
        for iteration in range(100):
            current_port = base_port + (iteration * 10)
            
            # Cleanup previous iteration if any
            subprocess.run(["pkill", "-f", f"shamir-party.x.*{test_name}"], capture_output=True)
            time.sleep(0.1)
            
            # Run parties
            parties = []
            for party_id in range(m):
                p = subprocess.Popen(
                    ["./shamir-party.x", "-N", str(m), "-p", str(party_id), "-h", "localhost", "-pn", str(current_port), test_name],
                    cwd=mp_spdz_root,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                parties.append(p)
                # Small stagger launch
                time.sleep(0.05)
            
            # Collect output with timeout
            outputs = []
            errors = []
            iteration_success = False

            try:
                for p in parties:
                    try:
                        out, err = p.communicate(timeout=5)
                        outputs.append(out)
                        errors.append(err)
                    except subprocess.TimeoutError:
                        p.kill()
                        outputs.append("")
                        errors.append("Timeout")
            except Exception as e:
                print(f"E({iteration})", end="", flush=True)
                failures += 1
                continue

            # Parse Party 0 output for x2 (index 1)
            x2_val = None
            if outputs and outputs[0]:
                for line in outputs[0].split('\n'):
                    if 'u[1] =' in line:
                        try:
                            # Parse u[1] = val
                            parts = line.split('=')
                            if len(parts) > 1:
                                x2_val = int(parts[1].strip())
                        except:
                            pass
            
            if x2_val is not None:
                results[x2_val] = results.get(x2_val, 0) + 1
                print(".", end="", flush=True)
                iteration_success = True
            else:
                print("x", end="", flush=True)
                failures += 1
                if failures == 1 and errors: # Print first failure details
                    print(f"\n  First failure stderr (Party 0): {errors[0]}")
        
        print("\n  Statistical Results (100 iterations):")
        print(f"  x2 = 0: {results.get(0, 0)} times")
        print(f"  x2 = 1: {results.get(1, 0)} times")
        print(f"  Failures/Timeouts: {failures}")
        
        # Cleanup file
        if mpc_file.exists():
            mpc_file.unlink()


    def test_sum_of_weights(self):
        """
        Test that the solver minimizes the sum of weights of violated clauses,
        not just the count of violated clauses.
        
        Clauses:
        1. (x1 v x2) [w varies]
        2. (~x1 v ~x2) [w=1]
        3. (x1 v ~x2) [w=1]
        4. (~x1 v x2) [w=1]
        5. (~x1) [w=1]
        6. (~x2) [w=1]
        """
        clauses = [[1, 2], [-1, -2], [1, -2], [-1, 2], [-1], [-2]]
        n = 2
        m = 6
        
        # Scenario 1: Uniform weights (all 1)
        # x1=0, x2=0 violates only clause 1 (cost 1).
        # x1=0, x2=1 violates clauses 3, 6 (cost 2).
        # x1=1, x2=0 violates clauses 4, 5 (cost 2).
        # x1=1, x2=1 violates clauses 2, 5, 6 (cost 3).
        print("\\n  Running Scenario 1 (Weights=1)...")
        is_solved, satisfied, assignment = compile_and_run_mpc(
            test_name="test_sum_weights_uni",
            clauses=clauses,
            n=n,
            m=m,
            weights=[1.0] * 6,
            description="Sum of Weights Test: Uniform weights"
        )
        assert assignment[0] == 0 and assignment[1] == 0, f"Scenario 1 failed: Expected x1=0, x2=0, got {assignment}"
        print("  ✓ Scenario 1 passed: Minimized violations count.")

        # Scenario 2: Clause 1 weight = 10
        # x1=0, x2=0 violates clause 1 (cost 10).
        # x1=0, x2=1 violates clauses 3, 6 (cost 2).
        # x1=1, x2=0 violates clauses 4, 5 (cost 2).
        # Should switch to (0,1) or (1,0).
        print("\\n  Running Scenario 2 (Clause 1 Weight=10)...")
        is_solved, satisfied, assignment = compile_and_run_mpc(
            test_name="test_sum_weights_heavy",
            clauses=clauses,
            n=n,
            m=m,
            weights=[10.0, 1.0, 1.0, 1.0, 1.0, 1.0],
            description="Sum of Weights Test: Heavy weight first clause"
        )
        assert not (assignment[0] == 0 and assignment[1] == 0), "Scenario 2 failed: Should perform better than (0,0)"
        valid_others = (assignment[0] == 0 and assignment[1] == 1) or (assignment[0] == 1 and assignment[1] == 0)
        assert valid_others, f"Scenario 2 failed: Expected (0,1) or (1,0), got {assignment}"
        print("  ✓ Scenario 2 passed: Avoided expensive clause 1.")

        # Scenario 3: Clause 1 weight = 1.5
        # x1=0, x2=0 violates clause 1 (cost 1.5).
        # Others cost 2.
        # Should return to (0,0).
        print("\\n  Running Scenario 3 (Clause 1 Weight=1.5)...")
        is_solved, satisfied, assignment = compile_and_run_mpc(
            test_name="test_sum_weights_border",
            clauses=clauses,
            n=n,
            m=m,
            weights=[1.5, 1.0, 1.0, 1.0, 1.0, 1.0],
            description="Sum of Weights Test: Weight 1.5 first clause"
        )
        assert assignment[0] == 0 and assignment[1] == 0, f"Scenario 3 failed: Expected x1=0, x2=0, got {assignment}"
        print("  ✓ Scenario 3 passed: Correctly prioritized sum of weights (1.5 < 2.0).")


