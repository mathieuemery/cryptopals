# Source: https://datatracker.ietf.org/doc/html/rfc2945

import hashlib
import hmac
import secrets

N = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF
g = 2
k = 3

def sha256(value):
    """
    Generate the SHA256 hash of a value.
    """
    return hashlib.sha256(value).hexdigest()

def to_int(hex_string):
    """
    Convert a hex string into an integer.
    """
    return int(hex_string, 16)

class Server:
    def __init__(self, email, password):
        """
        Init the internal state of the server.
        """
        self.I = email
        self.P = password

        self.salt = secrets.randbits(16)
        
        xH = sha256(
            str(self.salt).encode() + self.P.encode()
        )
        x = to_int(xH)

        self.v = pow(g, x, N)
    
    def receive_A(self, email, A):
        """
        Handle the email and the public key of the client.
        """
        self.A = A

        self.b = secrets.randbelow(N)
        self.B = (k * self.v + pow(g, self.b, N)) % N

        return self.salt, self.B

    def compute_K(self):
        """
        Compute K from the two public keys (A and B)
        """
        uH = sha256(
            str(self.A).encode() + str(self.B).encode()
        )
        u = to_int(uH)

        S = pow(self.A * pow(self.v, u, N), self.b, N)
        self.K = sha256(str(S).encode())

    def verify(self, client_hmac):
        """
        Verify the MAC from the client.
        """
        expected = hmac.new(
            self.K.encode(),
            str(self.salt).encode(),
            hashlib.sha256
        ).hexdigest()

        return hmac.compare_digest(expected, client_hmac)

    
class Client:
    def __init__(self, email, password):
        """
        Init the internal state of the client.
        """
        self.I = email,
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
        Compute K from the two public keys (A and B),
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
            B - k * pow(g, x, N),
            self.a + u * x,
            N
        )
        self.K = sha256(str(S).encode())

        return hmac.new(
            self.K.encode(),
            str(salt).encode(),
            hashlib.sha256
        ).hexdigest()
