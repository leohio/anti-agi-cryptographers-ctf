from curve.curve import G1
from curve.pairing import *
from problem import *

pk1,sk1 = keyGen()
pk2,sk2 = keyGen()

signature1 = M*sk1
signature2 = M*sk2
signature = signature1*(make_weight(pk1.x.val)) + signature2*(make_weight(pk2.x.val))

P = pk1*(make_weight(pk1.x.val)) + pk2*(make_weight(pk2.x.val))

print("BLS signature verify : ",pairing(G1,signature) == pairing(P,M))