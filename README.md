# 🔥 CTF Scripts Collection - **Finders Keepers Challenge**

This repository contains a set of **Capture The Flag (CTF) challenge scripts** used to solve various security and cryptographic challenges. Each script is specialized for a unique challenge scenario, from **radio signal analysis** to **minesweeper automation**, **obfuscated string decryption**, **cookie prediction**, and **network-based authentication bypass**.

Additionally, this repository includes a **steganography-based challenge** called **"Finders Keepers"**, which involves extracting hidden data from images and audio files using various forensic techniques.

## 📜 Table of Contents

- [oldSkool.py](#oldskoolpy) - Radio Signal Processing
- [minesweep2.py](#minesweep2py) - Minesweeper Solver
- [loginator.py](#loginatorpy) - Obfuscated String Reversal
- [cookies.py](#cookiespy) - Predictive Cookie Cracker
- [HotPause.py](#hotpausepy) - Network Authentication Solver
- [Finders Keepers (Steganography Challenge)](#🔍-finders-keepers-steganography-challenge)

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

## 🔍 **Finders Keepers (Steganography Challenge)**

### 🎯 Challenge:
- Extract **hidden files** embedded in an image (`weird.png`).
- Decode a **Morse code message** from an extracted **WAV audio**.
- Use **steganographic techniques** to reveal a hidden text file (`flag.txt`).

### 🔧 Steps:

#### **1️⃣ Extract Hidden Files**
```bash
foremost -i weird.png -o extracted_files
```
- This will generate an `extracted_files/` directory containing:
  - `extracted_hidden.jpg` (Hidden JPEG)
  - `extracted_audio.wav` (Hidden WAV)

#### **2️⃣ Decode the Audio (Morse Code)**
- **Go to:** [🔗 Morse Code Audio Decoder](https://morsecode.world/international/decoder/audio-decoder-adaptive.html)
- **Upload** `extracted_audio.wav`
- **Extract the passphrase** (decoded from Morse code).

#### **3️⃣ Extract Hidden Data from the JPEG**
Once the **passphrase** is obtained, use `steghide` to extract hidden content from the **JPEG**:

```bash
steghide extract -sf extracted_hidden.jpg -p "snooooooppppppp"
```

This will **reveal a hidden file (`flag.txt`)**.

#### **4️⃣ Read the Flag**
```bash
cat flag.txt
```

**🏆 Final CTF Flag:**
```
BITSCTF{1_4m_5l33py_1256AE76}
```

---

## 🤝 Contributing

Feel free to **fork** this repo, submit **pull requests**, or suggest improvements.

---

## 📜 License

This project is licensed under the **MIT License**.

---

🔥 **Happy CTFing!** 🚀
