"""
setup_email.py

One-time interactive setup for SMTP email delivery via Gmail App Password.

WHY A SCRIPT INSTEAD OF EDITING .env BY HAND
--------------------------------------------
A Gmail App Password is a live credential. Typing it into a chat window puts
it in that conversation's history permanently. This script prompts for it in
your own terminal, so it never leaves your machine.

WHAT IT DOES
------------
  1. Checks you have an App Password (from myaccount.google.com/apppasswords)
  2. Prompts for your Gmail address and the App Password (input hidden)
  3. Writes SMTP_* into .env and disables the Resend key so the SMTP
     transport is selected automatically
  4. Sends a real test email to yourself to prove it works

RUN IT
------
    python setup_email.py
"""

import getpass
import os
import re
import smtplib
import sys
from email.message import EmailMessage

ENV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587


def read_env_lines():
    if not os.path.exists(ENV_PATH):
        return []
    with open(ENV_PATH, "r", encoding="utf-8") as f:
        return f.read().splitlines()


def upsert_env(lines, key, value):
    """Set key=value in place, or append it. Preserves comments and order."""
    prefix = f"{key}="
    for i, line in enumerate(lines):
        if line.strip().startswith(prefix):
            lines[i] = f"{key}={value}"
            return lines
    lines.append(f"{key}={value}")
    return lines


def write_env(lines):
    with open(ENV_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(lines).rstrip() + "\n")


def main():
    preset = sys.argv[1].strip() if len(sys.argv) > 1 else ""

    print("=" * 68)
    print(" SMTP EMAIL SETUP (Gmail App Password)")
    print("=" * 68)
    print()
    print("Send FROM your own Gmail account -> deliver TO anyone.")
    print("No domain purchase, no DNS records, no Resend verification.")
    print()
    print("Before continuing, create an App Password for that Gmail:")
    print("  1. Turn on 2-Step Verification for the Google account")
    print("  2. Open  https://myaccount.google.com/apppasswords")
    print("  3. Create a password named e.g. 'QCTD Reports'")
    print("  4. Google shows a 16-character password -- copy it")
    print()
    print("That password is typed here, never sent anywhere.")
    print()

    if not os.path.exists(ENV_PATH):
        print(f"[!] No .env found at {ENV_PATH}")
        sys.exit(1)

    if preset:
        gmail = preset
        print(f"Gmail address (sending mailbox): {gmail}   [pre-filled, press Enter to accept]")
        entered = input("> ").strip()
        if entered:
            gmail = entered
    else:
        gmail = input("Gmail address (the sending mailbox): ").strip()

    if not gmail or "@" not in gmail:
        print("[x] That does not look like an email address.")
        sys.exit(1)

    print()
    print("Now paste the 16-character App Password. It will NOT be echoed.")
    app_password = getpass.getpass("App Password: ").strip().replace(" ", "")

    if len(app_password) < 16:
        print(f"[x] That looks too short ({len(app_password)} chars).")
        print("    Google App Passwords are 16 characters. Spaces are removed")
        print("    automatically, so check you copied the whole thing.")
        sys.exit(1)

    sender = input("\nFrom name (default 'QCTD Reports'): ").strip() or "QCTD Reports"

    lines = read_env_lines()
    lines = upsert_env(lines, "SMTP_HOST", SMTP_HOST)
    lines = upsert_env(lines, "SMTP_PORT", str(SMTP_PORT))
    lines = upsert_env(lines, "SMTP_USER", gmail)
    lines = upsert_env(lines, "SMTP_PASSWORD", app_password)
    lines = upsert_env(lines, "SMTP_USE_TLS", "1")
    lines = upsert_env(lines, "REPORT_FROM_EMAIL", f'"{sender} <{gmail}>"')

    # Clear the Resend key so EmailService selects the SMTP transport.
    for i, line in enumerate(lines):
        if line.strip().startswith("RESEND_API_KEY="):
            lines[i] = "RESEND_API_KEY="

    write_env(lines)
    print("\n[+] .env updated.")

    print("\nTesting the connection...")
    message = EmailMessage()
    message["From"] = f"{sender} <{gmail}>"
    message["To"] = gmail
    message["Subject"] = "QCTD - SMTP setup verified"
    message.set_content(
        "Your SMTP transport is configured. Reports can now be sent to any "
        "recipient address."
    )

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=25) as server:
            server.starttls()
            server.login(gmail, app_password)
            server.send_message(message)
    except smtplib.SMTPAuthenticationError:
        print("[x] Authentication failed.")
        print("    Common causes:")
        print("      - 2-Step Verification is not enabled on the Google account")
        print("      - the App Password was revoked after creation")
        print("      - a regular account password was pasted instead")
        sys.exit(1)
    except Exception as e:
        print(f"[x] Connection failed: {type(e).__name__}: {e}")
        print("    Check your network/firewall allows outbound port 587.")
        sys.exit(1)

    print(f"[+] Test email sent to {gmail}")
    print("=" * 68)
    print(" DONE. Restart the Streamlit app to pick this up:")
    print("     streamlit run app.py")
    print("=" * 68)


if __name__ == "__main__":
    main()