# Point at infinity
# Reference: crypto lessons

class EllipticCurve:
    def __init__(self, p, a, b):
        self.p, self.a, self.b = p, a, b


    def point(self, x, y):
        return EllipticPoint(x, y, self)


    def infinity(self):
        return EllipticPoint(None, None, self)


class EllipticPoint:
    def __init__(self, x, y, curve):
        self.x, self.y, self.curve = x, y, curve


    @property
    def is_infinity(self):
        return self.x is None and self.y is None


    def __eq__(self, other):
        return (self.curve is other.curve
                and self.x == other.x and self.y == other.y)


    def __repr__(self):
        if self.is_infinity:
            return "O"
        return f"({self.x}, {self.y})"


    def invert(self):
        if self.is_infinity:
            return self
        return EllipticPoint(
            self.x,
            -self.y % self.curve.p,
            self.curve
        )

    
    def _point_doubling(self):
        """
        Formula is:
        λ = (3 * x^2 + a) / (2 * y)
        xr = λ² - 2x
        yr = -yp + λ(xp - xr)
        """
        p = self.curve.p

        num = (3 * pow(self.x, 2, p) + self.curve.a) % p
        den = (2 * self.y) % p

        lam = (num * pow(den, -1, p)) % p

        xr = (pow(lam, 2, p) - 2 * self.x) % p
        yr = (lam * (self.x - xr) - self.y) % p

        return EllipticPoint(xr, yr, self.curve)

    
    def _point_addition(self, other):
        """
        For R(xr, yr) = P + Q, the formula is:
        xr = (yq - yp)² - xp - xq
        yr = -yp + (yq - yp)/(xq - xp) * (xp - xr)
        """
        p = self.curve.p

        x1, y1 = self.x , self.y
        x2, y2 = other.x, other.y

        num = (y2 - y1) % p
        den = (x2 - x1) % p

        lam = (num * pow(den, -1, p)) % p

        xr = (pow(lam, 2, p) - x1 - x2) % p
        yr = (lam * (x1 - xr) - y1) % p

        return EllipticPoint(xr, yr, self.curve)
    

    def add(self, other):
        """
        Add two elliptic curve points.
        """
        if self.curve is not other.curve:
            raise ValueError("Points must belong to the same curve")

        if self.is_infinity:
            return other

        if other.is_infinity:
            return self

        if self.x == other.x:
            if self.y != other.y or self.y == 0:
                return self.curve.infinity()   # P + (-P) = O

            return self._point_doubling()

        return self._point_addition(other)


    def scale(self, k):
        """
        Double-and-add: returns k * self.
        """
        result = self.curve.infinity()
        addend = self
        while k > 0:
            if k & 1:
                result = result.add(addend)
            addend = addend.add(addend)
            k >>= 1
            
        return result