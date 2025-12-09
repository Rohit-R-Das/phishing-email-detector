import re

suspicious_keywords = [
    "urgent", "verify your account", "limited time", "password expired",
    "click here", "update now", "login immediately", "attention", "important notice"
]

suspicious_domains = [
    "bit.ly", "tinyurl", "rb.gy", "freegift", "winprize"
]


def check_phishing(email_text):
    issues = []
    score = 0

    # 1. Check for suspicious keywords
    for word in suspicious_keywords:
        if word in email_text.lower():
            issues.append(f"⚠️ Suspicious keyword found: '{word}'")
            score += 1

    # 2. Check for links + suspicious domains
    urls = re.findall(r'(https?://\S+)', email_text)
    for url in urls:
        for bad_domain in suspicious_domains:
            if bad_domain in url:
                issues.append(f"⚠️ Suspicious shortened/malicious URL: {url}")
                score += 1

    # 3. Check for requests for sensitive information
    if re.search(r"(password|otp|bank|credit card|ssn)", email_text.lower()):
        issues.append("⚠️ Email asks for sensitive information!")
        score += 1

    # 4. Check for poor spelling (simple check)
    if re.search(r"\brecieve\b|\bsecurty\b|\bverfy\b", email_text.lower()):
        issues.append("⚠️ Spelling mistakes commonly seen in phishing emails")
        score += 1

    # Determine risk level
    if score >= 4:
        status = "🚨 HIGH RISK — Likely a phishing email"
    elif score >= 2:
        status = "⚠️ MEDIUM RISK — Possible phishing"
    else:
        status = "✅ LOW RISK — Email looks safe"

    return status, issues, urls


if __name__ == "__main__":
    print("📧 Phishing Email Detector\n")
    print("Paste the email content below (press Enter twice to finish):\n")

    lines = []
    while True:
        line = input()
        if line == "":
            break
        lines.append(line)

    email_content = "\n".join(lines)

    status, issues, urls = check_phishing(email_content)

    print("\n🔍 Analysis Result:")
    print(status)

    if urls:
        print("\n🧷 Links Found:")
        for u in urls:
            print("-", u)

    if issues:
        print("\n⚠️ Issues Detected:")
        for i in issues:
            print("-", i)
