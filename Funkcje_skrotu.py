import tkinter as tk
from tkinter import ttk, messagebox
import hashlib
import os
import time
import matplotlib.pyplot as plt
import random
import string
import numpy as np
# Bartosz Kozlowski 155869
# Lista funkcji skrótu
hash_algorithms = {
    'MD5': hashlib.md5,
    'SHA-1': hashlib.sha1,
    'SHA-224': hashlib.sha224,
    'SHA-256': hashlib.sha256,
    'SHA-384': hashlib.sha384,
    'SHA-512': hashlib.sha512,
    'SHA3-224': hashlib.sha3_224,
    'SHA3-256': hashlib.sha3_256,
    'SHA3-384': hashlib.sha3_384,
    'SHA3-512': hashlib.sha3_512
}

# GUI główne okno
window = tk.Tk()
window.title("Generator i Analiza Funkcji Skrótu")
window.geometry("750x600")
window.configure(bg="#f7f7f7")

style = ttk.Style()
style.theme_use("clam")
style.configure("TButton", padding=6, relief="flat", background="#4CAF50", foreground="white", font=('Segoe UI', 10, 'bold'))
style.configure("TLabel", background="#f7f7f7", font=('Segoe UI', 10))
style.configure("TEntry", font=('Segoe UI', 10))
style.configure("TCombobox", font=('Segoe UI', 10))

# --- Funkcje ---
def generate_hash():
    text = input_text.get()
    algorithm = selected_algorithm.get()
    if not text:
        messagebox.showwarning("Błąd", "Wprowadź tekst do zaszyfrowania!")
        return
    hash_func = hash_algorithms[algorithm]
    result = hash_func(text.encode()).hexdigest()
    result_var.set(result)

def copy_to_clipboard():
    value = result_var.get()
    if value:
        window.clipboard_clear()
        window.clipboard_append(value)
        messagebox.showinfo("Skopiowano", "Wynik został skopiowany do schowka.")
    else:
        messagebox.showwarning("Brak danych", "Najpierw wygeneruj skrót.")

def print_digest_lengths():
    output = "Długości digestów (digest vs hexdigest):\n"
    example_input = b"example input"
    for name, func in hash_algorithms.items():
        d = len(func(example_input).digest())
        h = len(func(example_input).hexdigest())
        output += f"{name:10s}: {d} bajtów, {h} znaków hex\n"
    messagebox.showinfo("Długości Digestów", output)

def generate_random_string(min_length=10, max_length=10000):
    length = random.randint(min_length, max_length)
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def analyze_collisions():
    algorithm = selected_algorithm.get()
    hash_func = hash_algorithms[algorithm]
    prefixes = {}
    collisions = 0
    num_inputs = 1000

    for _ in range(num_inputs):
        text = generate_random_string()
        hash_hex = hash_func(text.encode()).hexdigest()
        prefix = hash_hex[:3]  # 3 znaki hex = 12 bitów  5 - 20 bitow  12 - 48 bitow

        if prefix in prefixes:
            collisions += 1
        else:
            prefixes[prefix] = text

    messagebox.showinfo(f"Kolizje w {algorithm} (12 bitów)",
                        f"Zbadano {num_inputs} losowych wejść.\nLiczba kolizji 12-bitowego prefiksu: {collisions}")


def sac_selected():
    algorithm = selected_algorithm.get()
    hash_func = hash_algorithms[algorithm]

    def compute_digest(data):
        return hash_func(data).digest()

    def toggle_bit(data, index):
        byte_index = index // 8
        bit_in_byte = index % 8
        new_byte = data[byte_index] ^ (1 << bit_in_byte)
        return data[:byte_index] + bytes([new_byte]) + data[byte_index+1:]

    def count_bit_flips(h1, h2):
        return sum(bin(b1 ^ b2).count('1') for b1, b2 in zip(h1, h2))

    data = os.urandom(64)
    original = compute_digest(data)
    total_flips = 0
    digest_length_bits = len(original) * 8

    for i in range(len(data) * 8):
        altered = toggle_bit(data, i)
        altered_hash = compute_digest(altered)
        total_flips += count_bit_flips(original, altered_hash)

    average = total_flips / (len(data) * 8)
    probability = average / digest_length_bits
    messagebox.showinfo(f"Efekt lawiny – {algorithm}",
                        f"Średnia liczba zmienionych bitów: {average:.2f}\n"
                        f"Prawdopodobieństwo zmiany: {probability:.3f}")
    
def draw_bar_chart(results):
    labels = list(next(iter(results.values())).keys())  # algorytmy
    x = np.arange(len(labels))  # pozycje słupków
    width = 0.25

    plt.figure(figsize=(12, 6))
    for i, (size, times) in enumerate(results.items()):
        values = [times[algo] for algo in labels]
        plt.bar(x + i * width, values, width=width, label=f"{size}MB")

    plt.xlabel("Funkcja skrótu")
    plt.ylabel("Średni czas (s)")
    plt.title("Benchmark funkcji skrótu")
    plt.xticks(x + width, labels, rotation=30)
    plt.legend()
    plt.grid(True, axis='y')
    plt.tight_layout()
    plt.savefig("benchmark_bar.pdf")
    plt.savefig("benchmark_bar.png", dpi=300)
    plt.show()

REPEATS = 100  # liczba powtórzeń

def benchmark():
    file_sizes = [1, 5, 10]
    results = {size: {} for size in file_sizes}
    with open("benchmark_results.txt", "w") as f:
        for size in file_sizes:
            data = ("A" * (size * 1024 * 1024)).encode()
            f.write(f"Rozmiar pliku: {size}MB\n")
            for name, func in hash_algorithms.items():
                total_duration = 0
                for _ in range(REPEATS):
                    start = time.perf_counter()  # dokładniejszy pomiar
                    func(data).hexdigest()
                    total_duration += time.perf_counter() - start
                avg_duration = total_duration / REPEATS
                results[size][name] = avg_duration
                f.write(f"{name:10s} : {avg_duration:.10f} s\n")
            f.write("\n")
    draw_bar_chart(results)

# --- GUI Layout ---
tk.Label(window, text="Wprowadź tekst:", bg="#f7f7f7", font=('Segoe UI', 10)).pack(pady=5)
input_text = ttk.Entry(window, width=60)
input_text.pack(pady=5)

selected_algorithm = tk.StringVar(value='SHA-256')
tk.Label(window, text="Wybierz funkcję skrótu:", bg="#f7f7f7", font=('Segoe UI', 10)).pack(pady=5)
combo = ttk.Combobox(window, textvariable=selected_algorithm, values=list(hash_algorithms.keys()), state="readonly", width=20)
combo.pack(pady=5)

tk.Button(window, text="Generuj skrót", command=generate_hash, bg="#4CAF50", fg="white", font=('Segoe UI', 10, 'bold')).pack(pady=10)

result_var = tk.StringVar()
result_label = tk.Entry(window, textvariable=result_var, font=("Courier New", 10), width=80, state='readonly', readonlybackground="#ffffff")
result_label.pack(pady=5, padx=20)

tk.Button(window, text="Skopiuj do schowka", command=copy_to_clipboard, bg="#2196F3", fg="white", font=('Segoe UI', 10)).pack(pady=5)

# Dodatkowe funkcje
frame = tk.Frame(window, bg="#f7f7f7")
frame.pack(pady=20)

tk.Button(frame, text="Benchmark", command=benchmark).grid(row=0, column=0, padx=10, pady=5)
tk.Button(frame, text="Długości digestów", command=print_digest_lengths).grid(row=0, column=1, padx=10, pady=5)
tk.Button(frame, text="Kolizje (12 bit)", command=analyze_collisions).grid(row=0, column=2, padx=10, pady=5)
tk.Button(frame, text="Efekt lawiny", command=sac_selected).grid(row=0, column=3, padx=10, pady=5)

# Uruchomienie GUI
window.mainloop()