#!/usr/bin/env python3
"""
Minesweeper 2 defuser (robust version for higher levels)

- Reads the printed board (hints) from the server.
- Uses PuLP to solve for the minimal mine counts.
- Builds a complete list of moves (each move being a coordinate that must be played as many times as the mine count).
- Sends moves in rapid succession (with a short delay) without waiting for a reply after each move.
- Periodically reads available output to stay in sync with the server.
- Works with boards that change each level and with up to 65,536 moves.
"""

import re
import sys
import time
from pwn import remote
import pulp

# -------------------------
# Board parsing and solving
# -------------------------

def parse_board(data):
    """
    Extracts rows of numbers from the received data.
    Expects lines that are composed of space-separated digits.
    Returns a 2D list of integers.
    """
    lines = data.decode(errors="replace").splitlines()
    board = []
    for line in lines:
        if re.match(r"^\s*(\d+\s+)+\d+\s*$", line):
            row = [int(x) for x in line.strip().split()]
            board.append(row)
    return board

def solve_board(hints):
    """
    Given a 2D list `hints` (the printed numbers), solve for the mine counts.
    Each cell's hint equals the sum of mines in its 4 adjacent neighbors.
    We use an integer linear program that minimizes the total number of mines.
    Returns a 2D list of computed mine counts.
    """
    R = len(hints)
    C = len(hints[0])
    prob = pulp.LpProblem("Minesweeper2", pulp.LpMinimize)

    # Create variables for each cell
    x = {}
    for i in range(R):
        for j in range(C):
            x[(i,j)] = pulp.LpVariable(f"x_{i}_{j}", lowBound=0, cat="Integer")
    
    # Objective: minimize total mines
    prob += pulp.lpSum(x[(i,j)] for i in range(R) for j in range(C)), "TotalMines"

    # For each board cell, the sum of mines in the four adjacent cells must equal the hint.
    for i in range(R):
        for j in range(C):
            neighbor_vars = []
            for di, dj in [(-1,0), (1,0), (0,-1), (0,1)]:
                ni, nj = i + di, j + dj
                if 0 <= ni < R and 0 <= nj < C:
                    neighbor_vars.append(x[(ni,nj)])
            prob += pulp.lpSum(neighbor_vars) == hints[i][j], f"Constraint_{i}_{j}"

    # Solve with the default CBC solver.
    prob.solve()
    if pulp.LpStatus[prob.status] != "Optimal":
        sys.exit("No optimal solution found. Status: " + pulp.LpStatus[prob.status])

    sol = [[int(pulp.value(x[(i,j)])) for j in range(C)] for i in range(R)]
    return sol

# -------------------------
# Move sending helper
# -------------------------

def send_moves(r, moves, delay=0.01, periodic_delay=0.02):
    """
    Sends moves (a list of strings) on the remote connection `r` without waiting
    for a reply after every move. A short `delay` is added after each move.
    Every 50 moves (for example) we attempt a non-blocking read to flush any output.
    """
    count = 0
    for move in moves:
        r.sendline(move)
        count += 1
        # A very short delay between moves
        time.sleep(delay)
        # Every 50 moves, do a quick non-blocking read (if available) so that the connection stays in sync.
        if count % 50 == 0:
            try:
                _ = r.clean(timeout=periodic_delay)
            except Exception:
                pass

# -------------------------
# Main loop
# -------------------------

def main():
    host = "chals.bitskrieg.in"
    port = 7005

    # Connect to the challenge server.
    try:
        r = remote(host, port)
    except Exception as e:
        sys.exit(f"Error connecting to {host}:{port} - {e}")
    
    print(f"[*] Connected to {host}:{port}")
    
    while True:
        try:
            # Read data until we see the prompt "Enter your move"
            data = r.recvuntil(b"Enter your move", timeout=10)
        except Exception as e:
            print("Error receiving data:", e)
            break

        # Print the data (optional)
        sys.stdout.write(data.decode(errors="replace"))
        sys.stdout.flush()
        
        # Look for the board text. The board is printed after a line like "Here is your board:".
        if b"Here is your board:" in data:
            board_data = data.split(b"Here is your board:")[1]
            hints = parse_board(board_data)
            if not hints:
                # Try to read one more line if the board is split
                extra = r.recvline(timeout=1)
                hints = parse_board(extra)
            if not hints:
                print("Failed to parse board.", file=sys.stderr)
                continue
            
            print("[*] Parsed board (hints):")
            for row in hints:
                print("  " + " ".join(f"{n:2d}" for n in row))
            
            # Compute the mine counts.
            mines = solve_board(hints)
            print("[*] Computed mine counts:")
            for row in mines:
                print("  " + " ".join(f"{n:2d}" for n in row))
            
            # Build the complete move list.
            moves = []
            R_board = len(mines)
            C_board = len(mines[0])
            total_moves = 0
            for i in range(R_board):
                for j in range(C_board):
                    count = mines[i][j]
                    total_moves += count
                    for _ in range(count):
                        # Adjust coordinates if needed (e.g. flipping columns) depending on challenge details.
                        moves.append(f"{i} {j}")
            
            print(f"[*] Sending {len(moves)} moves for this level (allowed moves: 65536).")
            # Send all moves without waiting for each move's reply.
            send_moves(r, moves, delay=0.005, periodic_delay=0.02)
            
            # After sending moves for this level, try to read the response that confirms level clearance.
            try:
                level_reply = r.recvuntil(b"You have cleared the level!", timeout=5)
                print("[*] Level reply:")
                sys.stdout.write(level_reply.decode(errors="replace"))
                sys.stdout.flush()
            except Exception as e:
                print("Error reading level reply:", e)
            
            # A short delay before attempting to read the next board.
            time.sleep(0.2)
        else:
            # If no board was found, simply continue.
            time.sleep(0.1)
    
    r.interactive()

if __name__ == "__main__":
    main()






"""Answer:- BITSCTF{D0_u_y34rn_f0R_th3_m1n3s?}"""
