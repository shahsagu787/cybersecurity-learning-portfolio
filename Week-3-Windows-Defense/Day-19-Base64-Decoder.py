# Day 19: SOC PowerShell Base64 (UTF-16LE) Decoder
import base64

encoded_cmd = "VwByAGkAdABlAC0ASABvAHMAdAAgACcASABlAGwAbABvACAAUwBPAEMAJwA="
print(f"[*] Encoded Payload : {encoded_cmd}")

raw_bytes = base64.b64decode(encoded_cmd)
decoded_text = raw_bytes.decode("utf-16le")

print(f"[+] Decoded Command : {decoded_text}")