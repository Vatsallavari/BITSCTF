'''analysis'''
import numpy as np
import matplotlib.pyplot as plt
import scipy.signal as signal

# Extract the signal centered at 6 kHz
center_freq = 6000  # Hz

# Mix the signal down to baseband
t = np.arange(len(iq_data)) / sampling_rate
baseband_signal = iq_data * np.exp(-1j * 2 * np.pi * center_freq * t)

# Check for AM by extracting the envelope
am_envelope = np.abs(baseband_signal)

# Check for FM by computing the phase difference
fm_derivative = np.angle(baseband_signal[1:] * np.conj(baseband_signal[:-1]))

# Plot both AM and FM signals
plt.figure(figsize=(12, 5))

plt.subplot(2, 1, 1)
plt.plot(am_envelope, label="AM Envelope", color="blue")
plt.title("AM Envelope Detection")
plt.xlabel("Samples")
plt.ylabel("Amplitude")
plt.legend()
plt.grid()

plt.subplot(2, 1, 2)
plt.plot(fm_derivative, label="FM Derivative", color="red")
plt.title("FM Frequency Variations")
plt.xlabel("Samples")
plt.ylabel("Frequency Shift")
plt.legend()
plt.grid()

plt.tight_layout()
plt.show()

# Check modulation type based on signal strength
am_power = np.mean(am_envelope)
fm_power = np.mean(np.abs(fm_derivative))

(am_power, fm_power)


'''audio'''
import soundfile as sf

# Load the audio file
audio_file_path = "/mnt/data/demodulated_audio.wav"
audio_data, original_sample_rate = sf.read(audio_file_path)

# Slow down the audio by a factor (e.g., 2x slower)
slow_factor = 2.0  # Adjust this factor as needed
new_sample_rate = int(original_sample_rate / slow_factor)

# Save the slowed-down audio
slow_audio_file_path = "/mnt/data/demodulated_audio_slow.wav"
sf.write(slow_audio_file_path, audio_data, new_sample_rate)

# Provide the slowed-down audio file for download
slow_audio_file_path

'''slowing audio'''
import soundfile as sf

# Load the audio file
audio_file_path = "/mnt/data/demodulated_audio.wav"
audio_data, original_sample_rate = sf.read(audio_file_path)

# Slow down the audio by a factor (e.g., 2x slower)
slow_factor = 2.0  # Adjust this factor as needed
new_sample_rate = int(original_sample_rate / slow_factor)

# Save the slowed-down audio
slow_audio_file_path = "/mnt/data/demodulated_audio_slow.wav"
sf.write(slow_audio_file_path, audio_data, new_sample_rate)

# Provide the slowed-down audio file for download
slow_audio_file_path




"""BITSCTF{welcome_to_our_radio_enjoy_our_song_collection}"""
