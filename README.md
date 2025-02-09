Here is a **GitHub README** write-up for your repository containing the scripts:

---

# 🔥 BITS-CTF Scripts Collection

This repository contains a set of **Capture The Flag (CTF) challenge scripts** used to solve various security and cryptographic challenges. Each script is specialized for a unique challenge scenario, from **radio signal analysis** to **minesweeper automation**, **obfuscated string decryption**, **cookie prediction**, and **network-based authentication bypass**.

## 📜 Table of Contents

- [oldSkool.py](#oldskoolpy) - Radio Signal Processing
- [minesweep2.py](#minesweep2py) - Minesweeper Solver
- [loginator.py](#loginatorpy) - Obfuscated String Reversal
- [cookies.py](#cookiespy) - Predictive Cookie Cracker
- [HotPause.py](#hotpausepy) - Network Authentication Solver

---

## 📡 oldSkool.py

### 🎯 Challenge:
- Extract and analyze **modulated radio signals** (AM/FM).
- Slow down **demodulated** audio signals for analysis.

### 🔧 Features:
- **Baseband signal extraction** centered at **6 kHz**.
- **AM envelope detection** and **FM frequency variation analysis**.
- **Audio slow-down processing** to improve playback clarity.

### 🖥️ Usage:
```bash
python oldSkool.py
```
#### 📌 Expected Output:
- **Two plots**: AM envelope & FM variations.
- **A slowed-down audio file** for further inspection.

#### 🏆 CTF Flag:
```
BITSCTF{welcome_to_our_radio_enjoy_our_song_collection}
```

---

## 💣 minesweep2.py

### 🎯 Challenge:
- Automate **minesweeper** solving using **Integer Linear Programming (ILP)**.

### 🔧 Features:
- **Parses minesweeper hints** from the server.
- Uses **PuLP optimization** to find minimal mines.
- **Sends rapid moves** efficiently while staying in sync.

### 🖥️ Usage:
```bash
python minesweep2.py
```
#### 📌 Expected Output:
- Minesweeper **grid parsed** from the challenge.
- **Optimized moves** are executed to clear the board.

#### 🏆 CTF Flag:
```
BITSCTF{D0_u_y34rn_f0R_th3_m1n3s?}
```

---

## 🔐 loginator.py

### 🎯 Challenge:
- Reverse-engineer **byte-level obfuscation** logic.

### 🔧 Features:
- **Four-step transformation reversal**:
  - XOR manipulations
  - Multiplication/division-based encoding
  - Left/right bit rotations
  - Bitwise complement logic

### 🖥️ Usage:
```bash
python loginator.py
```
#### 📌 Expected Output:
- **Recovered plaintext** from obfuscated data.

#### 🏆 CTF Flag:
```
BITSCTF{C4ND4C3_L0G1C_W0RK?}
```

---

## 🍪 cookies.py

### 🎯 Challenge:
- **Predict the server's cookie choices** based on **pseudo-random sequences**.

### 🔧 Features:
- **Reconstructs the server’s PRNG state** (using `libc.rand()`).
- **Predicts the next correct cookie** selection.
- Automates **100 correct guesses in a row**.

### 🖥️ Usage:
```bash
python cookies.py
```
#### 📌 Expected Output:
- The script correctly **guesses 100 cookies** in sequence.

#### 🏆 CTF Flag:
```
BITSCTF{7h4nk5_f0r_4ll_0f_th3_c00ki3s_1_r34lly_enjoy3d_th3m_d31fa51e}
```

---

## 🎭 HotPause.py

### 🎯 Challenge:
- **Authenticate through a three-stage challenge** using socket-based automation.

### 🔧 Features:
- **Auto-solves three challenge stages**:
  - **City name validation**
  - **Seat block identification**
  - **Final encoded data submission**
- Uses **TCP socket handling** for rapid authentication.

### 🖥️ Usage:
```bash
python HotPause.py
```
#### 📌 Expected Output:
- Successfully **authenticates** and prints the **final challenge response**.

#### 🏆 CTF Flag:
```
BITSCTF{that_was_a_very_weird_OSINT_challenge_afd12df}
```

---

## 🚀 Getting Started

### 📦 Prerequisites:
- Python **3.x**
- Dependencies: Install via `pip`:
  ```bash
  pip install -r requirements.txt
  ```

### ⚡ Running the Scripts:
Each script is **standalone** and can be executed directly:
```bash
python script_name.py
```

---

## 🤝 Contributing

Feel free to **fork** this repo, submit **pull requests**, or suggest improvements.

---

## 📜 License

This project is licensed under the **MIT License**.

---

🔥 **Happy CTFing!** 🚀
