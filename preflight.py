"""
preflight.py

Run this BEFORE the demo. It checks every dependency of the two-phone setup
and tells you exactly what to fix if something is wrong.

The failure modes this catches are the ones that otherwise fail silently on
stage:

  * The venv was built on another machine (paths point at someone else's
    username, so every command in it errors out).
  * Windows Firewall is blocking inbound connections, so the phones simply
    never load the page and there is no useful error to debug.
  * The laptop and the phones are on different networks, so the LAN address
    is unreachable even though localhost works fine.
  * qiskit / flask are missing, so the server dies on startup.

Usage:
    python preflight.py
    python preflight.py --ip 192.168.1.42      # check a specific LAN address
"""

import argparse
import os
import socket
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OK, WARN, FAIL = "[ OK ]", "[WARN]", "[FAIL]"
results = []


def check(name, status, detail=""):
    results.append((name, status, detail))
    print(f"{status} {name}" + (f"\n         {detail}" if detail else ""))


def check_python():
    exe = sys.executable
    broken = "OneDrive\\Documents" in exe or "Vinayak" in exe
    if broken:
        check("Python environment", FAIL,
              f"Running from a foreign venv path: {exe}\n"
              f"         Delete .venv and run: python -m venv .venv")
        return
    check("Python environment", OK, f"{sys.version.split()[0]} at {exe}")

    if os.path.isdir(os.path.join(HERE, ".venv")):
        venv_py = os.path.join(HERE, ".venv", "Scripts", "python.exe")
        if not os.path.exists(venv_py):
            check("Local .venv", FAIL, ".venv exists but has no interpreter")
        else:
            try:
                out = subprocess.run([venv_py, "--version"], capture_output=True,
                                     text=True, timeout=30)
                check("Local .venv", OK if out.returncode == 0 else FAIL,
                      out.stdout.strip() or out.stderr.strip()[:80])
            except Exception as e:
                check("Local .venv", FAIL, str(e)[:80])
    else:
        check("Local .venv", WARN, "No .venv here. Using system Python (fine, but "
                                   "teammates will need to create one).")


def check_imports():
    missing = []
    for mod, pip_name in [("qiskit", "qiskit"), ("qiskit_aer", "qiskit-aer"),
                          ("numpy", "numpy"), ("flask", "flask"),
                          ("streamlit", "streamlit")]:
        try:
            __import__(mod)
        except ImportError:
            missing.append(pip_name)

    if missing:
        check("Dependencies", FAIL,
              f"Missing: {', '.join(missing)}\n"
              f"         Fix with: pip install -r requirements.txt")
    else:
        check("Dependencies", OK, "qiskit, qiskit-aer, numpy, flask, streamlit present")


def lan_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return None
    finally:
        s.close()


def check_network(ip):
    from network import candidate_addresses, HOTSPOT_PREFIX

    print("\n" + "=" * 66)
    print(" NETWORK")
    print("=" * 66)

    cands = candidate_addresses()

    if not cands:
        check("Network address", FAIL,
              "No usable IPv4 address. Is this machine connected to a network?")
        return None

    for addr, alias in cands:
        if addr.startswith(HOTSPOT_PREFIX):
            tag = "Windows hotspot adapter"
        elif "Ethernet" in alias:
            tag = "Ethernet (venue network)"
        elif "Wi-Fi" in alias:
            tag = "Wi-Fi"
        else:
            tag = alias
        check("Address", OK, f"{addr}  [{tag}]")

    primary = cands[0][0]
    hotspot = [c for c in cands if c[0].startswith(HOTSPOT_PREFIX)]

    if hotspot:
        print("\n  A hotspot was detected. If your phones joined THIS laptop's")
        print("  hotspot, they must use:")
        print(f"      http://{hotspot[0][0]}:5000")
        print("  They cannot reach the Ethernet/Wi-Fi address on the venue network.")
        print("  If they are instead on the venue router, use that address instead.")

    s = socket.socket()
    try:
        s.bind(("0.0.0.0", 5000))
        check("Port 5000", OK, "free")
    except OSError:
        check("Port 5000", WARN, "already in use -- server.py may be running")
    finally:
        s.close()

    return primary


def check_firewall():
    print("\n" + "=" * 66)
    print(" FIREWALL")
    print("=" * 66)

    if os.name != "nt":
        check("Firewall", OK, "not Windows; skipping")
        return

    try:
        out = subprocess.run(
            ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
            capture_output=True, text=True, timeout=40)
        text = out.stdout.lower()
        has_inbound = "python" in text
        enabled = "enabled" in text

        if has_inbound and enabled:
            check("Firewall", OK, "inbound rule for python.exe present")
        elif has_inbound:
            check("Firewall", WARN,
                  "A python rule exists but may be disabled. Re-enable it, or the "
                  "phones will not connect.")
        else:
            check("Firewall", FAIL,
                  "No inbound rule for python.exe.\n"
                  "         Start server.py and, when Windows prompts, choose "
                  "ALLOW on PRIVATE networks.\n"
                  "         If you missed the prompt, run the command below.")
            print("\n         To add it manually (run PowerShell as Administrator):")
            print('         netsh advfirewall firewall add rule name="QDS Demo" '
                  'dir=in action=allow protocol=TCP localport=5000')
    except Exception as e:
        check("Firewall", WARN, f"could not inspect: {e}")


def check_db():
    print("\n" + "=" * 66)
    print(" STATE")
    print("=" * 66)

    db = os.path.join(HERE, "qds_sessions.db")
    if os.path.exists(db):
        size = os.path.getsize(db)
        check("Session database", OK, f"{db} ({size:,} bytes) -- gitignored")
    else:
        check("Session database", OK, "not created yet (server.py makes it)")

    env = os.path.join(HERE, ".env")
    if os.path.exists(env):
        has_smtp = False
        has_email = False
        try:
            with open(env, encoding="utf-8") as f:
                for line in f:
                    if line.startswith("SMTP_PASSWORD=") and "=" in line:
                        has_smtp = len(line.split("=", 1)[1].strip()) >= 16
                    if line.startswith("RESEND_API_KEY=") and line.split("=", 1)[1].strip():
                        has_email = True
        except Exception:
            pass

        if has_smtp:
            check("Email transport", OK, "SMTP configured (Gmail App Password)")
        elif has_email:
            check("Email transport", OK, "Resend key configured")
        else:
            check("Email transport", WARN,
                  "No email transport configured. Run: python setup_email.py")
    else:
        check(".env", WARN, "missing -- copy .env.example and fill it in")


def main():
    print("=" * 66)
    print(" QDS PHONE DEMO -- PREFLIGHT CHECK")
    print("=" * 66)

    parser = argparse.ArgumentParser()
    parser.add_argument("--ip", help="LAN address to verify")
    args = parser.parse_args()

    check_python()
    check_imports()
    ip = args.ip or lan_ip()
    check_network(ip)
    check_firewall()
    check_db()

    print("\n" + "=" * 66)
    fails = [r for r in results if r[1] == FAIL]
    warns = [r for r in results if r[1] == WARN]

    if fails:
        print(f" RESULT: {len(fails)} BLOCKING ISSUE(S), {len(warns)} warning(s)")
        for name, _, detail in fails:
            print(f"   - {name}")
        print("\n Fix the blocking issues above before the demo.")
    else:
        print(f" RESULT: READY ({len(warns)} warning(s))")
        from network import candidate_addresses
        cands = candidate_addresses()
        if cands:
            print("\n On your phones, open the address matching how they connected:")
            for addr, alias in cands:
                tag = "  <- hotspot (phones joined THIS laptop)" \
                    if addr.startswith("192.168.137.") else ""
                print(f"   http://{addr}:5000{tag}")
        print("\n Phones and this laptop must be on the SAME network.")
    print("=" * 66)


if __name__ == "__main__":
    main()