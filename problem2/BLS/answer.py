from curve.curve import G1
from curve.pairing import pairing
from problem import make_weight, pk1, M, send_signature

# The problem can be solved by setting:
#   sig = w1 * M
#   pk2 = G1 - pk1
# where w1 = make_weight(pk1) and vice versa.
# For this, the BLS signature check equation will be
#   e(G, w1 * M) ?= e(w1 * pk1 + w2 * pk2, M)
#   e(G, w1 * M) ?= e(w1 * G, M)
# which will pass the test.
#
# Note that w1 = w2 for the given pubkeys.
#
# If not, search n for which pk2 = n * G - pk1 has the same weight with pk1, and set
#   sig = n * w1 * M
#   pk2 = n * G1 - pk1

# Compute the answer.
pk2 = G1 + (-pk1)
w1 = make_weight(pk1.x.val)
w2 = make_weight(pk2.x.val)
sig = w1 * M

# Check the answer.
P = w1 * pk1 + w2 * pk2
e1 = pairing(G1, sig)
e2 = pairing(P, M)
print(e1 == e2)

# Send the answer.
send_signature(sig, pk2)

### Solved first by Vis Virial (@visvirial).
