import base64
import binascii
import socket


def run_port_check() -> None:
    """Option 1: Checks whether a single TCP port is open on an authorized target."""
    # Prompt the user for a target host/IP and remove surrounding whitespace
    host = input("Enter authorized target host (e.g., scanme.nmap.org): ").strip()
    if not host:
        print("[!] Invalid input: Host cannot be empty.")
        return

    # Prompt for a port number and ensure it parses as an integer
    port_raw = input("Enter target port (1-65535): ").strip()
    try:
        port = int(port_raw)
    except ValueError:
        print("[!] Invalid input: Port must be a whole number.")
        return

    # Validate that the port falls within the standard TCP/UDP range (1-65535)
    if not (1 <= port <= 65535):
        print("[!] Invalid input: Port must be between 1 and 65535.")
        return

    print(f"[*] Checking {host}:{port} (authorized target only)...")
    # Create an IPv4 TCP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Set a 2-second timeout so unreachable hosts do not hang the script
    sock.settimeout(2.0)

    try:
        # connect_ex() returns 0 when the TCP connection succeeds
        status = sock.connect_ex((host, port))
        if status == 0:
            print(f"[+] OPEN: {host}:{port} accepted a TCP connection.")
        else:
            print(f"[-] CLOSED/FILTERED: {host}:{port} did not accept a connection (code {status}).")
    except socket.gaierror:
        # Handle DNS resolution failures cleanly
        print(f"[!] Hostname error: Could not resolve '{host}'.")
    except OSError as exc:
        # Handle other socket/network errors without an unhandled traceback
        print(f"[!] Network error: {exc}")
    finally:
        # Always close the socket to release OS resources
        sock.close()


def run_log_counter() -> None:
    """Option 2: Counts 'Failed password' entries in a local log file safely."""
    log_path = input("Enter log file path (e.g., sample_auth.log): ").strip()
    if not log_path:
        print("[!] Invalid input: Log file path cannot be empty.")
        return

    search_term = "Failed password"
    failed_count = 0

    try:
        # Open the file using a context manager so it closes automatically
        with open(log_path, "r", encoding="utf-8", errors="replace") as file:
            # Iterate line by line with 1-based line numbers
            for line_num, line in enumerate(file, start=1):
                if search_term in line:
                    failed_count += 1
                    print(f"[#{failed_count} | Line {line_num}] {line.strip()}")
        print(f"[+] Scan complete: Found {failed_count} '{search_term}' entries in '{log_path}'.")
    except FileNotFoundError:
        print(f"[!] File not found: '{log_path}' does not exist.")
    except PermissionError:
        print(f"[!] Permission error: Cannot read '{log_path}'.")
    except OSError as exc:
        print(f"[!] File read error: {exc}")


def run_base64_decoder() -> None:
    """Option 3: Decodes Base64 text for display only; never executes output."""
    encoded_text = input("Enter Base64 string to decode: ").strip()
    if not encoded_text:
        print("[!] Invalid input: Base64 string cannot be empty.")
        return

    encoding_choice = input("Text encoding [1 = UTF-8 (standard), 2 = UTF-16LE (PowerShell)]: ").strip()
    if encoding_choice == "2":
        text_encoding = "utf-16le"
    elif encoding_choice in ("", "1"):
        text_encoding = "utf-8"
    else:
        print("[!] Invalid choice: Enter 1 for UTF-8 or 2 for UTF-16LE.")
        return

    try:
        # Decode Base64 with strict character validation, then decode text safely
        raw_bytes = base64.b64decode(encoded_text, validate=True)
        decoded_text = raw_bytes.decode(text_encoding)
        print("\n[+] Decoded Text (Display Only - Never Executed):")
        print("--------------------------------------------------")
        print(decoded_text)
        print("--------------------------------------------------")
    except (binascii.Error, ValueError):
        print("[!] Invalid Base64 input: Could not decode string.")
    except UnicodeDecodeError:
        print(f"[!] Decoding error: Bytes could not be decoded as {text_encoding.upper()}.")


def main() -> None:
    """Run the interactive menu loop until the user chooses to exit."""
    while True:
        print("\n=== Phase 1 Security Toolkit ===")
        print("1. Authorized Port Check")
        print("2. Failed-Login Log Counter")
        print("3. Base64 Text Decoder (Display Only)")
        print("4. Exit")

        choice = input("Select an option (1-4): ").strip()
        if choice == "1":
            run_port_check()
        elif choice == "2":
            run_log_counter()
        elif choice == "3":
            run_base64_decoder()
        elif choice == "4":
            print("Exiting toolkit. Stay safe!")
            break
        else:
            print("[!] Invalid menu choice. Please select 1, 2, 3, or 4.")


# Run main() only when this script is executed directly
if __name__ == "__main__":
    main()