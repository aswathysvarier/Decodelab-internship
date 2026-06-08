import re
import hmac

COMMON_PASSWORDS = {
    "password", "123456", "password123", "admin", "letmein",
    "qwerty", "abc123", "monkey", "1234567890", "111111",
    "iloveyou", "sunshine", "princess", "welcome", "shadow",
    "12345678", "dragon", "master", "666666", "password1"
}


def check_password_strength(password: str) -> dict:
    score = 0
    feedback = []

    # 1. Minimum length
    has_min_length = len(password) >= 8
    if has_min_length:
        score += 1
    else:
        feedback.append("❌ Password must be at least 8 characters long.")

    # 2. Good length bonus
    if len(password) >= 12:
        score += 1
        feedback.append("✅ Great length (12+ characters).")
    else:
        feedback.append("💡 Tip: Use 12+ characters for stronger security.")

    # 3. Uppercase
    has_upper = any(char.isupper() for char in password)
    if has_upper:
        score += 1
    else:
        feedback.append("❌ Add at least one UPPERCASE letter (A-Z).")

    # 4. Lowercase
    has_lower = any(char.islower() for char in password)
    if has_lower:
        score += 1
    else:
        feedback.append("❌ Add at least one lowercase letter (a-z).")

    # 5. Digit
    has_digit = any(char.isdigit() for char in password)
    if has_digit:
        score += 1
    else:
        feedback.append("❌ Add at least one number (0-9).")

    # 6. Symbol
    has_symbol = bool(re.search(r"[!@#$%^&*()\-_=+\[\]{};:'\",.<>?/\\|`~]", password))
    if has_symbol:
        score += 1
    else:
        feedback.append("❌ Add at least one special character (!@#$%^&* etc).")

    # 7. Not a common/leaked password
    is_common = any(hmac.compare_digest(password.lower(), c) for c in COMMON_PASSWORDS)
    if is_common:
        score = max(0, score - 2)
        feedback.append("⚠️  This password appears in leaked password lists!")
    else:
        score += 1
        feedback.append("✅ Not a commonly known/leaked password.")

    if score <= 2:
        strength = "🔴 WEAK"
        strength_bar = "█░░░░░░░░░"
    elif score <= 5:
        strength = "🟡 MEDIUM"
        strength_bar = "█████░░░░░"
    else:
        strength = "🟢 STRONG"
        strength_bar = "██████████"

    return {
        "score": score,
        "max_score": 7,
        "strength": strength,
        "strength_bar": strength_bar,
        "checks": {
            "min_length (>=8)":   has_min_length,
            "good_length (>=12)": len(password) >= 12,
            "has_uppercase":      has_upper,
            "has_lowercase":      has_lower,
            "has_digit":          has_digit,
            "has_symbol":         has_symbol,
            "not_common":         not is_common,
        },
        "feedback": feedback,
    }


def display_report(password: str, report: dict) -> None:
    masked = password[0] + ("*" * (len(password) - 2)) + password[-1] if len(password) > 2 else "***"
    print("\n" + "═" * 55)
    print("  🔐  PASSWORD STRENGTH REPORT")
    print("═" * 55)
    print(f"  Password  : {masked}   (length: {len(password)})")
    print(f"  Score     : {report['score']} / {report['max_score']}")
    print(f"  Strength  : {report['strength']}")
    print(f"  Meter     : [{report['strength_bar']}]")
    print()
    print("  ── CHECKS ──────────────────────────────────────")
    for check, passed in report["checks"].items():
        print(f"   {'✅' if passed else '❌'}  {check}")
    print()
    print("  ── FEEDBACK ─────────────────────────────────────")
    for tip in report["feedback"]:
        print(f"   {tip}")
    print("═" * 55 + "\n")


def main():
    print("\n" + "═" * 55)
    print("  🔐  Password Strength Checker")
    print("═" * 55)
    print("  Type a password to check its strength.")
    print("  Type 'quit' to stop.\n")

    while True:
        password = input("  Enter password: ").strip()
        if password.lower() in ("quit", "exit"):
            print("\n  🔒 Session ended. Stay secure!\n")
            break
        if not password:
            print("  ⚠️  No input detected. Please try again.\n")
            continue
        report = check_password_strength(password)
        display_report(password, report)


if __name__ == "__main__":
    main()
