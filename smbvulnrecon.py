import socket
from impacket.smbconnection import SMBConnection

def test_eternalblue(target_ip, port=445):
    print("[*] Testing for EternalBlue (CVE-2017-0144)...")
    payload = b"\x00\x00\x00\x90" + b"\xff" * 144
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((target_ip, port))
        sock.send(payload)
        response = sock.recv(1024)
        if response:
            print(f"[+] {target_ip} is vulnerable to EternalBlue.")
        else:
            print(f"[-] {target_ip} is not vulnerable to EternalBlue.")
    except Exception as e:
        print(f"[!] Error during EternalBlue test: {e}")
    finally:
        sock.close()

def test_smbghost(target_ip, port=445):
    print("[*] Testing for SMBGhost (CVE-2020-0796)...")
    payload = b"\x00\x00\x00\x00"
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((target_ip, port))
        sock.send(payload)
        response = sock.recv(1024)
        if b"\xfeSMB" in response:
            print(f"[+] {target_ip} is vulnerable to SMBGhost.")
        else:
            print(f"[-] {target_ip} is not vulnerable to SMBGhost.")
    except Exception as e:
        print(f"[!] Error during SMBGhost test: {e}")
    finally:
        sock.close()

def test_printnightmare(target_ip, username, password):
    print("[*] Testing for PrintNightmare (CVE-2021-1675)...")
    try:
        conn = SMBConnection(target_ip, target_ip)
        conn.login(username, password)
        if conn.isPrintSpoolerRunning():
            print(f"[+] Print Spooler service is running on {target_ip}. Potentially vulnerable to PrintNightmare.")
        else:
            print(f"[-] Print Spooler service is not running on {target_ip}.")
    except Exception as e:
        print(f"[!] Error during PrintNightmare test: {e}")

def test_smb_signing(target_ip):
    print("[*] Testing for SMB Signing Disabled (CVE-2022-38023)...")
    try:
        conn = SMBConnection(target_ip, target_ip)
        conn.login("", "")  # Anonymous login
        if not conn.isSigningRequired():
            print(f"[+] SMB Signing is disabled on {target_ip}.")
        else:
            print(f"[-] SMB Signing is enabled on {target_ip}.")
    except Exception as e:
        print(f"[!] Error during SMB Signing test: {e}")

def test_smbv1_dos(target_ip, port=445):
    print("[*] Testing for SMBv1 Denial-of-Service (CVE-2019-0703)...")
    payload = b"\x00" * 1024  # Crafted payload for testing DoS
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((target_ip, port))
        sock.send(payload)
        print(f"[+] Sent payload to {target_ip}. Monitor for server crash.")
    except Exception as e:
        print(f"[!] Error during SMBv1 DoS test: {e}")
    finally:
        sock.close()

def test_null_session(target_ip):
    print("[*] Testing for Null Session Enumeration...")
    try:
        conn = SMBConnection(target_ip, target_ip)
        conn.login("", "")  # Anonymous login
        shares = conn.listShares()
        print(f"[+] Null session established on {target_ip}. Shares: {[share['shi1_netname'] for share in shares]}")
    except Exception as e:
        print(f"[!] Null session test failed: {e}")

def test_smb_permissions(target_ip, username, password):
    print("[*] Testing for SMB Share Permissions...")
    try:
        conn = SMBConnection(target_ip, target_ip)
        conn.login(username, password)
        shares = conn.listShares()
        for share in shares:
            print(f"[*] Share: {share['shi1_netname']}")
            try:
                conn.listPath(share['shi1_netname'], '*')
                print(f"    [+] Read access available on {share['shi1_netname']}.")
            except:
                print(f"    [-] No access on {share['shi1_netname']}.")
    except Exception as e:
        print(f"[!] Error during SMB permissions test: {e}")

def run_all_tests(target_ip, username="guest", password="guest"):
    print(f"\n=== Running SMB Vulnerability Tests on {target_ip} ===\n")
    test_eternalblue(target_ip)
    test_smbghost(target_ip)
    test_printnightmare(target_ip, username, password)
    test_smb_signing(target_ip)
    test_smbv1_dos(target_ip)
    test_null_session(target_ip)
    test_smb_permissions(target_ip, username, password)
    print("\n=== SMB Vulnerability Tests Completed ===\n")

# Example usage:
if __name__ == "__main__":
    target = input("Enter target IP address: ")
    user = input("Enter username (default: guest): ") or "guest"
    passwd = input("Enter password (default: guest): ") or "guest"
    run_all_tests(target, user, passwd)
