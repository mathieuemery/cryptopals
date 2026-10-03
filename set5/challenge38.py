# Offline dictionary attack on simplified SRP

from primitives.srp import k, g, N, sha256, to_int
import secrets
import hashlib
import hmac

email = "test@test.com"

class MitmServer:
    """
    Simplified version of SRP.
    """
    def __init__(self, email):
        """
        Initiate the server's internal state.
        """
        self.I = email

        self.salt = secrets.randbits(16)
    
    def receive_A(self, A):
        """
        Handle the email and the public key of the client.
        """
        self.A = A

        self.b = secrets.randbelow(N)
        self.B = pow(g, self.b, N)

        return self.salt, self.B

    def compute_K(self, password):
        """
        Compute K from the public keys and
        the salt/password.
        """
        uH = sha256(
            str(self.A).encode() + str(self.B).encode()
        )
        u = to_int(uH)

        xH = sha256(
            str(self.salt).encode() + password.encode()
        )
        x = to_int(xH)

        self.v = pow(g, x, N)

        S = pow(self.A * pow(self.v, u, N), self.b, N)
        return sha256(str(S).encode())

    def crack_password(self, client_mac, words):
        """
        Offline dictionnary attack on the client's MAC.
        """
        for word in words:
            K = self.compute_K(word)

            candidate_mac = hmac.new(
                K.encode(),
                str(self.salt).encode(),
                hashlib.sha256
            ).hexdigest()

            if hmac.compare_digest(candidate_mac, client_mac):
                return word

        print("Password not found")
        return None

class MitmClient:
    def __init__(self, email, password):
        """
        Initiate the clients's internal state.
        """
        self.I = email
        self.P = password

        self.a = secrets.randbelow(N)
        self.A = pow(g, self.a, N)

    def send_A(self):
        """
        Send the email and its public key.
        """
        return self.I, self.A

    def compute_K(self, salt, B):
        """
        Compute the MAC from the two public keys (A and B),
        the salt and password.
        """
        uH = sha256(
            str(self.A).encode() + str(B).encode()
        )
        u = to_int(uH)

        xH = sha256(
            str(salt).encode() + self.P.encode()
        )
        x = to_int(xH)

        S = pow(
            B,
            self.a + u * x,
            N
        )
        self.K = sha256(str(S).encode())

        return hmac.new(
            self.K.encode(),
            str(salt).encode(),
            hashlib.sha256
        ).hexdigest()


def random_password(words):
    """
    Select a random password in a list of words.
    """
    random_word = secrets.choice(words)

    print("Chosen word", random_word)
    
    return random_word


def dictionary_attack():
    """
    Chose a random password, compute a MAC on the
    client's side and then crack it on the server's side
    with an offline dictionary attack.
    """
    with open("data/dict.txt", "r", encoding="utf-8") as f:
        # Use a subset to make the attack faster
        words = f.read().split()[:1000]

    server = MitmServer(email)

    client = MitmClient(
        email,
        random_password(words)
    )

    # C -> S
    I, A = client.send_A()

    # S -> C
    salt, B = server.receive_A(A)

    # S, C
    client_hmac = client.compute_K(salt, B)

    pwd = server.crack_password(client_hmac, words)

    if pwd is not None:
        print("Found the password: ", pwd)


if __name__ == "__main__":
    dictionary_attack()