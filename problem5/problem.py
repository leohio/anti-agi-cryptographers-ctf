from fielddef import FQFac

q = 115792089210356248762697446949407573529996955224135760342422259061068512044369
GF = FQFac(q)

G = (GF(68001253697693959505385166418825921216879992913338607518506263877231417389309), GF(32956869957026046537418079256725634934468928549809562050419661008417397548252))
P = (GF(78682525735928631168497251673563130650852315793053792730195256219768651938341), GF(84795375029059674300362179151585264542663827440804066060768991521034056440120))

d = 1 #??? This is TARGET. P = dG
SuperP = (GF(78682525735928631168497251673563130650852315793053792730195256219768651938341), GF(40426504872605514126813907278243558543227238540609187742567326172940715852589))
# Super Elliptic Curve 1 + 3 x + 4 x^2 + 4 x^3 + 3 x^4 + x^5


### For your convinience.
class EllipticCurve():

    def __init__(self, a, b, c, d, prime):
        if a == 0:
            raise ValueError("a=0 is forbidden!")
        self.a = GF(a)
        self.b = GF(b)
        self.c = GF(c)
        self.d = GF(d)
        self.prime = prime

    def isin(self, p):
        if p == 0:
            return True
        x, y = p[0], p[1]
        value = y**2 - self.a * (x ** 3) - self.b * (x**2) - self.c * x - self.d
        if value== GF(0):
            return True
        return False

    def sum(self, p, q):
        if not self.isin(p):
            raise ValueError("{} is not in the elliptic curve".format(p))
        if not self.isin(q):
            raise ValueError("{} is not in the elliptic curve".format(q))

        if p == 0:
            return q
        if q == 0:
            return p
        x1, y1 = p[0], p[1]
        x2, y2 = q[0], q[1]

        if x1 != x2:
            x3 = self.a.inv() * ((y2-y1)*(x2-x1).inv()) ** 2 - self.b*self.a.inv() - x1 - x2
            y3 = (y2-y1)*(x2-x1).inv() * -x3 + (y2*x1 - y1*x2)*(x2 - x1).inv()
            return (x3,y3)

        if x1 == x2 and y1 == -1 * y2:
            return 0

        if x1 == x2 and y1 != -1 * y2:
            x3 = (self.a ** 2  * x1 **4 - 2 * self.a * self.c * x1 ** 2\
                    - 8* self.a * self.d * x1 +  - 4 * self.b * self.d + self.c ** 2) * (4 * self.a * y1 ** 2).inv()

            y3 = (8 * self.a * y1 ** 3).inv()* ((self.a ** 3 * x1 ** 6)\
                    + 2 * self.a **2  * self.b * x1 ** 5\
                    + 5 * self.a**2 * self.c * x1 ** 4\
                    + 20 * self.a ** 2 * self.d * x1 ** 3\
                    + (20 * self.a * self.b * self.d - 5 * self.a * self.c **2) * x1**2\
                    + (8 * self.b**2 * self.d - 2 * self.b * self.c**2 - 4 * self.a * self.c * self.d) * x1\
                    + (4 * self.b * self.c * self.d - 8 * self.a * self.d**2  - self.c**3)
            )
            return (x3,y3)
        
    def mul(self, p, coefficient):

        coef = coefficient
        current = p
        result = 0
        while coef:
            if coef & 1:
                result = self.sum(result,current)
            current = self.sum(current,current)
            coef >>= 1
        return result