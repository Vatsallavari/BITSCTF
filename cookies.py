#!/usr/bin/env python3
"""
This script automates the challenge:
"Give me the cookie I want a 100 times in a row and I'll give you the flag!"

The server (20.244.40.210:6000) seeds its RNG with the current time and then selects a cookie:
    srand(time(NULL));
    index = rand() % 100;
It then compares your input to one of 100 hard‐coded cookie names.

This script uses Python’s ctypes to mimic libc’s srand/rand in order to predict the cookie.
It seeds the RNG once per connection and then calls rand() repeatedly to follow the sequence.
If a guess is wrong, the chain resets (and the connection is closed), and the script re‑connects.
Once 100 consecutive correct answers are achieved, the flag is printed.
"""

import time
import ctypes
from pwn import remote, log
from pwnlib.exception import PwnlibException

# List of 100 cookies (order must match the binary’s)
cookies = [
    "Chocolate Chip", "Sugar Cookie", "Oatmeal Raisin", "Peanut Butter",
    "Snickerdoodle", "Shortbread", "Gingerbread", "Macaron", "Macaroon", "Biscotti",
    "Butter Cookie", "White Chocolate Macadamia Nut", "Double Chocolate Chip",
    "M&M Cookie", "Lemon Drop Cookie", "Coconut Cookie", "Almond Cookie",
    "Thumbprint Cookie", "Fortune Cookie", "Black and White Cookie", "Molasses Cookie",
    "Pumpkin Cookie", "Maple Cookie", "Espresso Cookie", "Red Velvet Cookie",
    "Funfetti Cookie", "S'mores Cookie", "Rocky Road Cookie", "Caramel Apple Cookie",
    "Banana Bread Cookie", "Zucchini Cookie", "Matcha Green Tea Cookie",
    "Chai Spice Cookie", "Lavender Shortbread", "Earl Grey Tea Cookie",
    "Pistachio Cookie", "Hazelnut Cookie", "Pecan Sandies", "Linzer Cookie",
    "Spritz Cookie", "Russian Tea Cake", "Anzac Biscuit", "Florentine Cookie",
    "Stroopwafel", "Alfajores", "Polvor", "Springerle", "Pfeffern", "Speculoos",
    "Kolaczki", "Rugelach", "Hamantaschen", "Mandelbrot", "Koulourakia",
    "Melomakarona", "Kourabiedes", "Pizzelle", "Amaretti", "Cantucci",
    "Savoiardi (Ladyfingers)", "Madeleine", "Palmier", "Tuile", "Langue de Chat",
    "Viennese Whirls", "Empire Biscuit", "Jammie Dodger", "Digestive Biscuit",
    "Hobnob", "Garibaldi Biscuit", "Bourbon Biscuit", "Custard Cream",
    "Ginger Nut", "Nice Biscuit", "Shortcake", "Jam Thumbprint",
    "Coconut Macaroon", "Chocolate Crinkle", "Pepparkakor", "Sandbakelse",
    "Krumkake", "Rosette Cookie", "Pinwheel Cookie", "Checkerboard Cookie",
    "Rainbow Cookie", "Mexican Wedding Cookie", "Snowball Cookie",
    "Cranberry Orange Cookie", "Pumpkin Spice Cookie", "Cinnamon Roll Cookie",
    "Chocolate Hazelnut Cookie", "Salted Caramel Cookie", "Toffee Crunch Cookie",
    "Brownie Cookie", "Cheesecake Cookie", "Key Lime Cookie", "Blueberry Lemon Cookie",
    "Raspberry Almond Cookie", "Strawberry Shortcake Cookie", "Neapolitan Cookie"
]

# Load libc so we can use srand() and rand()
libc = ctypes.CDLL("libc.so.6")

def init_rng(seed):
    """Seed the RNG with the given seed (should match the server's seeding)."""
    libc.srand(seed)

def get_next_cookie():
    """
    Get the next cookie in the RNG sequence.
    Do not re-seed here; just call rand() once and use its result.
    """
    rand_val = libc.rand()
    index = rand_val % 100
    return cookies[index]

def attempt_chain():
    """
    Attempts to build a chain of 100 consecutive correct guesses.
    Returns (True, flag) if successful; otherwise (False, None).
    """
    try:
        r = remote("20.244.40.210", 6000)
    except Exception as e:
        log.error("Connection error: {}".format(e))
        return False, None

    # Seed our RNG once for this connection.
    # We assume the server does: srand(time(NULL))
    seed = int(time.time())
    log.info("Seeding RNG with: {}".format(seed))
    init_rng(seed)

    chain = 0
    log.info("Connected to 20.244.40.210:6000")
    try:
        while chain < 100:
            r.recvuntil("Guess the cookie:")
            predicted = get_next_cookie()
            log.info("Predicted cookie: {}".format(predicted))
            r.sendline(predicted)
            reply = r.recvline().decode().strip()
            log.info("Reply: {}".format(reply))
            if "Correct" in reply:
                chain += 1
                log.success("Chain: {}/100".format(chain))
            else:
                log.warning("Wrong guess. Reply: {}".format(reply))
                r.close()
                return False, None
        # After 100 correct responses, receive the flag.
        flag = r.recvall(timeout=5).decode()
        r.close()
        return True, flag
    except Exception as e:
        log.error("Error during chain: {}".format(e))
        r.close()
        return False, None

def main():
    while True:
        try:
            success, flag = attempt_chain()
        except PwnlibException as e:
            log.error("Attempt_chain exception: {}".format(e))
            success = False
            flag = None
        if success:
            log.success("Flag: {}".format(flag))
            break
        else:
            log.info("Chain broken or connection error. Retrying...")
            time.sleep(1)

if __name__ == "__main__":
    main()




"""BITSCTF{7h4nk5_f0r_4ll_0f_th3_c00ki3s_1_r34lly_enjoy3d_th3m_d31fa51e}"""
