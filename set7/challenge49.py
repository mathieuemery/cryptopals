# CBC-MAC Message Forgery

from primitives.aes_cbc import new_iv
from primitives.cbc_mac import create_mac, validate_mac, BLOCK_SIZE
from utils.fixed_xor import fixed_xor

key = b'YELLOW SUBMARINE'

def parse_request(request):
    """
    Extract the message, IV and MAC from the request.
    """
    if len(request) < 2 * BLOCK_SIZE:
        raise ValueError("The request is too small to have a mac and an IV")

    mac = request[-BLOCK_SIZE:]
    iv = request[-2 * BLOCK_SIZE:-BLOCK_SIZE]
    message = request[:-2 * BLOCK_SIZE]

    return message, iv, mac


def validate_message(request):
    """
    Validate a request with the structure:
    message || IV || MAC
    """
    msg, iv, mac = parse_request(request)

    if not validate_mac(msg, key, iv, mac):
        raise ValueError("Invalid MAC for this message")

    # Simulate doing a transaction
    print("Sending request:", msg)


def create_legitimate_message():
    # Here we say that our ID is the 45, this request is not for us
    intercepted_message = b'from=#12&to=#23&amount=#1000000'
    iv = new_iv()
    mac = create_mac(intercepted_message, iv, key)

    return intercepted_message, iv, mac


def user_generated_iv_attack():
    """
    Edit an intercepted request with the valid amount
    but where destination is not us.

    Knowing the ct = pt xor iv, we can edit the iv
    by doing new_iv = iv xor pt xor forged_pt.
    """
    inter_msg, iv, mac = create_legitimate_message()

    # We need to change the 'to' from '23' to '45'
    msg = bytearray(inter_msg)
    msg[13: 15] = b'45'
    print("Forged message:", msg)

    # Then we change the IV
    new_iv = fixed_xor(fixed_xor(iv, inter_msg[:BLOCK_SIZE]), msg[:BLOCK_SIZE])

    if validate_mac(msg, key, new_iv, mac):
        print("Successfully forged a message for a given mac")


if __name__ == "__main__":
    user_generated_iv_attack()