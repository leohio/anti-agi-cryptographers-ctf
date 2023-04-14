from curve.curve import Point, CurvePoint, G1, curve_order
from curve.curve_fields import FQ, FQ2, FQ12, BLS12_381_FQ_MODULUS as field_modulus

#number of iterations that Miller's loop algorithm requires
ate_loop_count = 15132376222941642752
log_ate_loop_count = 62

#returns the line between P1 and P2 evaluated in Q
def linefunc(P1: CurvePoint, P2: CurvePoint, Q: Point) -> FQ:
    if P1.is_infinite() or P2.is_infinite() or Q.is_infinite():
        raise ValueError("Can't compute line function on infinite point")

    x1, y1 = P1
    x2, y2 = P2
    xq, yq = Q

    if x1 != x2:
        m = (y2 - y1) / (x2 - x1)
        return m * (xq - x1) - (yq - y1)
    elif y1 == y2:
        m = 3 * x1**2 / (2 * y1)
        return m * (xq - x1) - (yq - y1)
    else:
        return xq - x1

#embeds a FQ point into a FQ12 point
def embed_FQ12(P: Point) -> Point:
    x, y = P
    return type(P)(FQ12(x), FQ12(y))

#algorithm which calculates pairing
def miller_loop(P: CurvePoint, Q: CurvePoint) -> FQ12:
    if P.is_infinite() or Q.is_infinite():
        return FQ12.one()

    R = Q
    f = FQ12.one()
    for i in range(log_ate_loop_count, -1, -1):
        f = f * f * linefunc(R, R, P)
        R = 2*R
        if ate_loop_count & (2**i):
            f = f * linefunc(R, Q, P)
            R = R + Q

    return f ** ((field_modulus ** 12 - 1) // curve_order)

    
def pairing(P: CurvePoint, Q: CurvePoint) -> FQ12:
    return miller_loop(embed_FQ12(P), Q.twist())
