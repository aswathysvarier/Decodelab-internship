import time


def caesar_encrypt(plaintext: str, shift: int) -> str:
    """Encrypt plaintext using Caesar Cipher.

    Formula: E(x) = (x + n) % 26
    - Letters are shifted; case is preserved.
    - Non-alphabetic characters (spaces, punctuation, digits)
      are passed through unchanged.
    """
    ciphertext = []
    for char in plaintext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            encrypted_char = chr((ord(char) - base + shift) % 26 + base)
            ciphertext.append(encrypted_char)
        else:
            ciphertext.append(char)          # preserve spaces / punctuation
    return "".join(ciphertext)


def caesar_decrypt(ciphertext: str, shift: int) -> str:
    """Decrypt ciphertext using Caesar Cipher.

    Formula: D(x) = (x - n) % 26
    Decryption is simply encryption with the negative shift.
    """
    return caesar_encrypt(ciphertext, -shift)


def display_banner():
    print("=" * 60)
    print("   Encryption & Decryption Tool")
    print("   Technique : Caesar Cipher")
    print("=" * 60)
    print()


def display_result(label: str, text: str):
    print(f"  {label:<20}: {text}")


def show_char_trace(plaintext: str, shift: int):
    """Show a step-by-step trace of the first alphabetic character."""
    for ch in plaintext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            ascii_val   = ord(ch)
            shifted_pos = (ascii_val - base + shift) % 26
            final_ascii = shifted_pos + base
            final_char  = chr(final_ascii)

            print(f"\n  [Algorithm Trace for '{ch}']")
            print(f"    1. ASCII value          : {ascii_val}")
            print(f"    2. Subtract base ({base})   : {ascii_val} - {base} = {ascii_val - base}")
            print(f"    3. Add shift key ({shift})   : {ascii_val - base} + {shift} = {ascii_val - base + shift}")
            print(f"    4. Modulo 26            : {ascii_val - base + shift} % 26 = {shifted_pos}")
            print(f"    5. Add base back ({base})  : {shifted_pos} + {base} = {final_ascii}")
            print(f"    6. Result character     : '{final_char}'")
            break


def get_shift_key() -> int:
    """Prompt user for a valid integer shift key."""
    while True:
        try:
            shift = int(input("  Enter shift key (1–25): ").strip())
            if 1 <= shift <= 25:
                return shift
            print("  [!] Shift key must be between 1 and 25. Try again.")
        except ValueError:
            print("  [!] Invalid input. Please enter an integer.")


def get_menu_choice() -> str:
    print("\n  OPTIONS:")
    print("  [1] Encrypt a message")
    print("  [2] Decrypt a message")
    print("  [3] Encrypt then auto-decrypt (full demo)")
    print("  [4] Exit")
    return input("\n  Choose an option (1/2/3/4): ").strip()


def run_encrypt(show_trace: bool = True):
    print("\n--- ENCRYPTION MODE ---")
    message = input("  Enter plaintext  : ")
    shift   = get_shift_key()

    start      = time.perf_counter()
    ciphertext = caesar_encrypt(message, shift)
    elapsed    = time.perf_counter() - start

    print()
    display_result("Original Text", message)
    display_result("Shift Key", str(shift))
    display_result("Encrypted Text", ciphertext)
    print(f"  {'Time Taken':<20}: {elapsed:.6f} seconds")

    if show_trace:
        show_char_trace(message, shift)

    return ciphertext, shift


def run_decrypt():
    print("\n--- DECRYPTION MODE ---")
    ciphertext = input("  Enter ciphertext : ")
    shift      = get_shift_key()

    start     = time.perf_counter()
    plaintext = caesar_decrypt(ciphertext, shift)
    elapsed   = time.perf_counter() - start

    print()
    display_result("Ciphertext", ciphertext)
    display_result("Shift Key", str(shift))
    display_result("Decrypted Text", plaintext)
    print(f"  {'Time Taken':<20}: {elapsed:.6f} seconds")


def run_full_demo():
    print("\n--- FULL DEMO: ENCRYPT → DECRYPT ---")
    message = input("  Enter plaintext  : ")
    shift   = get_shift_key()

    ciphertext = caesar_encrypt(message, shift)
    decrypted  = caesar_decrypt(ciphertext, shift)

    print()
    print("  " + "-" * 46)
    display_result("Original Text", message)
    display_result("Shift Key", str(shift))
    display_result("Encrypted Text", ciphertext)
    display_result("Decrypted Text", decrypted)
    print("  " + "-" * 46)

    match = "✅ Match — Decryption successful!" if message == decrypted else "❌ Mismatch — Check your logic."
    print(f"\n  Verification : {match}")

    show_char_trace(message, shift)


def main():
    display_banner()

    while True:
        choice = get_menu_choice()

        if choice == "1":
            run_encrypt()
        elif choice == "2":
            run_decrypt()
        elif choice == "3":
            run_full_demo()
        elif choice == "4":
            print("\n  Session ended. Stay secure! 🔐\n")
            break
        else:
            print("  [!] Invalid choice. Please enter 1, 2, 3, or 4.")

        print()


if __name__ == "__main__":
    main()
