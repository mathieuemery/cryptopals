# Implement Secure Remote Password (SRP)

from primitives.srp import Client, Server

def validate():
    """
    Validate that the server validates
    the client credentials.
    """
    server = Server(
        "alice@example.com",
        "password123"
    )

    client = Client(
        "alice@example.com",
        "password123"
    )

    # C -> S
    I, A = client.send_A()

    # S -> C
    salt, B = server.receive_A(I, A)

    # S, C
    client_hmac = client.compute_K(salt, B)
    server.compute_K()

    # C -> S
    # S -> C
    assert server.verify(client_hmac)

    print("Password was validated")

if __name__ == "__main__":
    validate()