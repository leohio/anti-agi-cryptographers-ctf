import numpy as np
from fielddef import FQFac
from qap import *

modq = 17064117955711778576537207979155607882504061569450183867868045703

input1 = 98347598347598739485798 ##random
input2 = input1**2
input3 = input2//modq

modres = input2%modq
input4 = input2 - modres

gate1 = [["c2"],["c1"],["c1"]]
gate2 = [["c4"],["c3"],[str(modq)]]
gate3 = [["c2"],["c4",str(modres)],[]]

gates = [gate1,gate2,gate3]
gmatrix = {"O":[],"L":[],"R":[]}
gmatrix = gates2LRO(gates)

tmatrix_o = np.array(gmatrix["O"]).T
tmatrix_l = np.array(gmatrix["L"]).T
tmatrix_r = np.array(gmatrix["R"]).T


polynomial_vector_o = lagrange(tmatrix_o)
polynomial_vector_l = lagrange(tmatrix_l)
polynomial_vector_r = lagrange(tmatrix_r)



witness = [GF(1),GF(input1),GF(input2),GF(input3),GF(input4)]
witness_e = [G*1,G*input1,G*input2,G*input3,G*input4]

final_polyvec_o = give_witness(polynomial_vector_o,witness)
final_polyvec_l = give_witness(polynomial_vector_l,witness) 
final_polyvec_r = give_witness(polynomial_vector_r,witness)

#tst = 1,2,3
tst = GF(2)
tstres = calc_poly(final_polyvec_o,tst)- calc_poly(final_polyvec_l,tst)*calc_poly(final_polyvec_r,tst)
if tstres.val>0:
    raise
print("TEST 1 done")


lr = polymul2Dx2D(final_polyvec_l,final_polyvec_r)

lro = polyadd(lr,final_polyvec_o,True)
print("TEST 2 eval=0:",calc_poly(lro,GF(2)))
b = polydiv(GF,lro,[GF(q-6),GF(11),GF(q-6),GF(1)])

s = GF(34875893)

zs = calc_poly([GF(q-6),GF(11),GF(q-6),GF(1)],s)
lros = calc_poly(lro,s)

print("TEST 3 equals:", lros==zs*calc_poly(b,s))

###
bG = [G*b[0].val,G*b[1].val]

hG = calc_poly(bG,s,True)
s_lro = G*num(lros)
print("TEST 4 equals:",s_lro==hG*num(zs))



s_o = calc_poly(give_witness(polynomial_vector_o,witness_e,True),s,True)
s_l = calc_poly(give_witness(polynomial_vector_l,witness_e,True),s,True)
n_r = calc_poly(final_polyvec_r,s)

print("TEST 5 equals:",s_l*num(n_r)+ -s_o==hG*num(zs))