from primitives.sha1 import SHA1
import secrets

key = secrets.token_bytes(16)

def compute_mac(message):
    return SHA1(key + message).hexdigest()

def verify_mac(message, mac):
    new_mac = compute_mac(message)

    return mac == new_mac