# Break SRP with a zero key
from primitives.srp import Client, Server, sha256, N
import hashlib
import hmac

def bypass_login(A):
    """
    Bypass the login using A = 0.

    If A = 0, the server will compute:
    S = (0 * v^u)^b mod N ) = 0
    K is then SHA256(0)
    """

    server = Server(
        "alice@example.com",
        "password123"
    )

    client = Client(
        "alice@example.com",
        "invalid_password"
    )

    K = sha256("0".encode())

    I, _ = client.send_A()
    salt, B = server.receive_A(I, A)

    forged_tag = hmac.new(
            K.encode(),
            str(salt).encode(),
            hashlib.sha256
        ).hexdigest()

    server.compute_K()

    assert server.verify(forged_tag)

    print("Successfully bypassed the login")


if __name__ == "__main__":
    for i in range(10):
        A = i * N
        print(f'Testing with A = {i} * N')

        bypass_login(A)