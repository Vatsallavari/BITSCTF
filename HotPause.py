#!/usr/bin/env python3
import socket
import time

HOST = "chals.bitskrieg.in"
PORT = 8000

def recv_until(s, marker, timeout=2):
    """
    Receives data from the socket until the marker string is found or timeout occurs.
    Returns the received data as a decoded string.
    """
    s.settimeout(timeout)
    data = b""
    try:
        while marker.encode() not in data:
            chunk = s.recv(1024)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    return data.decode(errors="ignore")

def attempt(candidate):
    """
    Opens a new connection to the server, goes through Stage 1 (City) and Stage 2 (Seat),
    and then sends the candidate string as the Stage 3 (Data Stream) answer.
    
    The entire exchange is printed to the console.
    
    :param candidate: The candidate answer (string) to send for Stage 3.
    :return: The final server response.
    """
    try:
        print(f"[+] Connecting to {HOST}:{PORT}...")
        s = socket.create_connection((HOST, PORT))
        
        # Stage 1: Provide the target city.
        stage1 = recv_until(s, "City Name (all caps):")
        print(stage1, end="")  # print the prompt exactly as received
        print("[>] Sending: AHMEDABAD")
        s.sendall("AHMEDABAD\n".encode())
        time.sleep(0.3)
        
        # Stage 2: Provide the partner agent's seat.
        stage2 = recv_until(s, "Block Letter with Bay")
        print(stage2, end="")
        print("[>] Sending: Q3")
        s.sendall("Q3\n".encode())
        time.sleep(0.3)
        
        # Stage 3: Wait for the Data Stream prompt.
        stage3 = recv_until(s, "Data Stream:")
        print(stage3, end="")
        
        # Send the candidate answer.
        print(f"[>] Sending: {candidate}")
        s.sendall((candidate + "\n").encode())
        time.sleep(0.3)
        
        # Get the final response (e.g., "Correct!" or "Wrong answer. Exiting...")
        final = recv_until(s, "\n", timeout=5)
        print(final.strip())
        s.close()
        return final
    except Exception as e:
        print("[!] Exception during attempt:", e)
        return ""

def main():
    # Candidate list using the new colors.
    # For each color, we include both the hex-code and some case variants.
    color_candidates = [
    # YEL:
    "1400 1400 700 700 700 700 1400 2800 700 2100 700 700 700 1400 700 1400 1400 2800 1400 2800 700"
    ]
    
    for candidate in color_candidates:
        print("\n" + "=" * 60)
        print(f"[*] Trying candidate: {candidate}")
        response = attempt(candidate)
        if response and "Correct!" in response:
            print(f"[+] Success with candidate: {candidate}")
            break
        else:
            print(f"[-] Candidate '{candidate}' did not succeed. (Connection closed, retrying next candidate...)")
            time.sleep(1)

if __name__ == '__main__':
    main()



"""BITSCTF{that_was_a_very_weird_OSINT_challenge_afd12df}"""
