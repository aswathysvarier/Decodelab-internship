import re


URGENCY_KEYWORDS = [
    "urgent", "immediately", "act now", "act fast", "right away",
    "as soon as possible", "expire", "expires", "expiring", "locked",
    "suspended", "final notice", "last chance", "within 24 hours",
    "within 30 minutes", "deadline", "respond immediately"
]

AUTHORITY_KEYWORDS = [
    "ceo", "cfo", "director", "manager", "hr department", "it support",
    "it security", "law enforcement", "government", "tax office",
    "legal action", "compliance team", "executive"
]

FEAR_GREED_KEYWORDS = [
    "account suspended", "unauthorized access", "unusual activity",
    "security alert", "you have won", "claim your prize", "free gift",
    "lottery", "refund", "payment failed", "invoice overdue",
    "legal action", "penalty", "fine"
]

CREDENTIAL_REQUEST_KEYWORDS = [
    "verify your password", "confirm your password", "enter your otp",
    "provide your pin", "social security number", "bank account number",
    "card number", "cvv", "login credentials", "verify your identity",
    "update your billing", "confirm your account"
]

SECRECY_BYPASS_KEYWORDS = [
    "do not discuss", "keep this confidential", "strictly confidential",
    "do not tell", "bypass standard procedure", "skip the usual process",
    "between us", "do not forward", "without informing"
]

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".click", ".info", ".club", ".loan", ".work", ".live"
]

LEGITIMATE_BRANDS = [
    "google", "microsoft", "amazon", "paypal", "apple", "facebook",
    "linkedin", "netflix", "chatgpt", "openai", "instagram", "bank"
]

DANGEROUS_ATTACHMENT_EXTENSIONS = [
    ".exe", ".scr", ".js", ".vbs", ".iso", ".bat", ".jar", ".lnk", ".hta"
]


def extract_urls(text):
    pattern = r'(?:https?://|www\.)[^\s<>"\']+'
    return re.findall(pattern, text, re.IGNORECASE)


def extract_domain(url):
    url = url.replace("http://", "").replace("https://", "")
    domain = url.split("/")[0]
    return domain.lower()


def check_sender_mismatch(display_name, sender_email):
    flags = []
    display_lower = display_name.lower()
    email_domain = sender_email.split("@")[-1].lower() if "@" in sender_email else ""

    for brand in LEGITIMATE_BRANDS:
        if brand in display_lower:
            if brand not in email_domain:
                flags.append(
                    f"Display name claims to be '{display_name}' but sender "
                    f"domain '{email_domain}' does not match the brand."
                )
            break

    free_email_providers = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com"]
    for brand in LEGITIMATE_BRANDS:
        if brand in display_lower and email_domain in free_email_providers:
            flags.append(
                f"Sender claims to represent '{brand.title()}' but is using a "
                f"free email provider ({email_domain}) instead of a corporate domain."
            )
            break

    return flags


def check_lookalike_domain(domain):
    flags = []

    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            flags.append(f"Domain '{domain}' uses an uncommon/high-risk TLD ({tld}).")

    if re.search(r'\d', domain):
        letters_with_digit_swap = re.sub(r'0', 'o', domain)
        letters_with_digit_swap = re.sub(r'1', 'l', letters_with_digit_swap)
        if letters_with_digit_swap != domain:
            flags.append(
                f"Domain '{domain}' contains digits that may be substituting "
                f"letters (typosquatting), e.g. 0 for o, 1 for l."
            )

    hyphen_count = domain.count("-")
    if hyphen_count >= 1:
        for brand in LEGITIMATE_BRANDS:
            if brand in domain and domain.replace(brand, "").strip("-.") != "":
                flags.append(
                    f"Domain '{domain}' combines a real brand name with extra "
                    f"words (combosquatting), a common impersonation tactic."
                )
                break

    labels = domain.split(".")
    if len(labels) > 3:
        flags.append(
            f"Domain '{domain}' has an unusually high number of subdomain "
            f"levels, which can be used to bury the real root domain."
        )

    return flags


def check_keywords(text, keyword_list, category_name):
    found = []
    text_lower = text.lower()
    for keyword in keyword_list:
        pattern = r'(?<!non-)(?<!non )\b' + re.escape(keyword) + r'\b'
        if re.search(pattern, text_lower):
            found.append(keyword)
    return found


def check_attachments(attachments):
    flags = []
    for attachment in attachments:
        for ext in DANGEROUS_ATTACHMENT_EXTENSIONS:
            if attachment.lower().endswith(ext):
                flags.append(
                    f"Attachment '{attachment}' uses a high-risk file "
                    f"extension ({ext}) commonly used to deliver malware."
                )
    return flags


def analyze_email(email):
    report = {
        "red_flags": [],
        "score": 0,
        "urls_found": [],
        "keyword_hits": {}
    }

    display_name = email.get("display_name", "")
    sender_email = email.get("sender_email", "")
    subject = email.get("subject", "")
    body = email.get("body", "")
    attachments = email.get("attachments", [])

    full_text = f"{subject} {body}"

    sender_flags = check_sender_mismatch(display_name, sender_email)
    report["red_flags"].extend(sender_flags)
    report["score"] += len(sender_flags) * 3

    urls = extract_urls(body)
    report["urls_found"] = urls
    for url in urls:
        domain = extract_domain(url)
        domain_flags = check_lookalike_domain(domain)
        report["red_flags"].extend(domain_flags)
        report["score"] += len(domain_flags) * 3

    urgency_hits = check_keywords(full_text, URGENCY_KEYWORDS, "Urgency")
    authority_hits = check_keywords(full_text, AUTHORITY_KEYWORDS, "Authority")
    fear_greed_hits = check_keywords(full_text, FEAR_GREED_KEYWORDS, "Fear/Greed")
    credential_hits = check_keywords(full_text, CREDENTIAL_REQUEST_KEYWORDS, "Credential Request")
    secrecy_hits = check_keywords(full_text, SECRECY_BYPASS_KEYWORDS, "Secrecy/Bypass")

    report["keyword_hits"] = {
        "Urgency": urgency_hits,
        "Authority": authority_hits,
        "Fear/Greed": fear_greed_hits,
        "Credential Request": credential_hits,
        "Secrecy/Bypass": secrecy_hits
    }

    if urgency_hits:
        report["red_flags"].append(
            f"Urgency language detected: {', '.join(urgency_hits)}."
        )
        report["score"] += 2

    if authority_hits:
        report["red_flags"].append(
            f"Authority impersonation language detected: {', '.join(authority_hits)}."
        )
        report["score"] += 2

    if fear_greed_hits:
        report["red_flags"].append(
            f"Fear or greed triggers detected: {', '.join(fear_greed_hits)}."
        )
        report["score"] += 2

    if credential_hits:
        report["red_flags"].append(
            f"Request for sensitive credentials/info detected: {', '.join(credential_hits)}."
        )
        report["score"] += 4

    if secrecy_hits:
        report["red_flags"].append(
            f"Secrecy or bypass-procedure language detected: {', '.join(secrecy_hits)}."
        )
        report["score"] += 4

    attachment_flags = check_attachments(attachments)
    report["red_flags"].extend(attachment_flags)
    report["score"] += len(attachment_flags) * 4

    if report["score"] >= 8:
        report["verdict"] = "MALICIOUS"
        report["action"] = "Block Domain & Escalate"
    elif report["score"] >= 3:
        report["verdict"] = "SUSPICIOUS"
        report["action"] = "Warn User"
    else:
        report["verdict"] = "SAFE"
        report["action"] = "Close"

    return report


def print_report(email_label, email, report):
    print("=" * 70)
    print(f"EMAIL: {email_label}")
    print("=" * 70)
    print(f"From: {email.get('display_name', '')} <{email.get('sender_email', '')}>")
    print(f"Subject: {email.get('subject', '')}")
    print("-" * 70)

    if report["urls_found"]:
        print("Links found:")
        for url in report["urls_found"]:
            print(f"  - {url}")
    else:
        print("Links found: none")

    print("-" * 70)
    if report["red_flags"]:
        print(f"Red flags identified ({len(report['red_flags'])}):")
        for i, flag in enumerate(report["red_flags"], start=1):
            print(f"  {i}. {flag}")
    else:
        print("Red flags identified: none")

    print("-" * 70)
    print(f"Risk score: {report['score']}")
    print(f"Verdict: {report['verdict']}")
    print(f"Recommended action: {report['action']}")
    print()


SAMPLE_EMAILS = [
    {
        "label": "Sample 1 - Fake IT Password Reset",
        "display_name": "IT Security",
        "sender_email": "support@logins-updates.com",
        "subject": "Mandatory: Your password expires in 24 hrs",
        "body": (
            "Dear Employee,\n\n"
            "Your account password will expire in 24 hours. To avoid being "
            "locked out, you must verify your password immediately using the "
            "link below.\n\n"
            "http://www.yourcompany.tech.login-update.com/reset\n\n"
            "This is urgent, please act now to prevent account suspension.\n\n"
            "IT Security Team"
        ),
        "attachments": []
    },
    {
        "label": "Sample 2 - Fake CEO Wire Transfer Request",
        "display_name": "CEO Name",
        "sender_email": "ceo.urgent@executive-update.com",
        "subject": "IMMEDIATE ACTION REQUIRED: Transfer Authorization",
        "body": (
            "I need you to process a wire transfer immediately. This is "
            "strictly confidential, do not discuss this with anyone else on "
            "the team. Bypass the standard procedure for this one, time is "
            "critical and I am unavailable by phone.\n\n"
            "Reply with confirmation once done.\n\n"
            "Thanks"
        ),
        "attachments": []
    },
    {
        "label": "Sample 3 - Fake Subscription Payment Failure",
        "display_name": "ChatGPT Billing",
        "sender_email": "billing@chatgpt-payments-update.xyz",
        "subject": "Urgent: Your subscription payment failed",
        "body": (
            "Your subscription payment failed. Please update your billing "
            "information immediately to avoid service interruption.\n\n"
            "Update here: http://chatgpt-payments-update.xyz/billing\n\n"
            "If you do not respond within 24 hours your account will be "
            "suspended."
        ),
        "attachments": ["Invoice_Details.iso"]
    },
    {
        "label": "Sample 4 - Legitimate Internal Email",
        "display_name": "Sarah Lee",
        "sender_email": "sarah.lee@company.com",
        "subject": "Q3 Project Status Update - Non-Urgent",
        "body": (
            "Hi Team,\n\n"
            "Please review the attached project status for Q3 at your "
            "earliest convenience. No immediate action is required.\n\n"
            "Thanks,\nSarah"
        ),
        "attachments": ["Q3_Status.pdf"]
    },
    {
        "label": "Sample 5 - Fake Bank Security Alert",
        "display_name": "Bank Security Team",
        "sender_email": "alerts@bank-secure-verify.club",
        "subject": "Unusual activity detected on your account",
        "body": (
            "We have detected unauthorized access on your account. To "
            "prevent further unauthorized access, please verify your "
            "identity and confirm your account by entering your login "
            "credentials and OTP at the secure link below.\n\n"
            "https://bank-secure-verify.club/verify-account\n\n"
            "Failure to respond within 30 minutes will result in your "
            "account being suspended."
        ),
        "attachments": []
    }
]


def run_all_samples():
    for email in SAMPLE_EMAILS:
        report = analyze_email(email)
        print_report(email["label"], email, report)


if __name__ == "__main__":
    run_all_samples()
