import numpy as np
from fielddef import FQFac
from qap import *
import json

modq = 17064117955711778576537207979155607882504061569450183867868045703

print("if the inputs are correct, you can run to the end. You can test QAP/ZKP in qap_test.py")
input1 = 12345 #change your input
input2 = input1**2
input3 = input2//modq

modres = 11400690601992899318043852838002104281963606996334908594893989568
input4 = input2 - modres

gate1 = [["c2"],["c1"],["c1"]]
gate2 = [["c4"],["c3"],[str(modq)]]
gate3 = [["c2"],["c4",str(modres)],[]]

gates = [gate1,gate2,gate3]
gmatrix = gates2LRO(gates)

tmatrix_o = np.array(gmatrix["O"]).T
tmatrix_l = np.array(gmatrix["L"]).T
tmatrix_r = np.array(gmatrix["R"]).T


polynomial_vector_o = lagrange(tmatrix_o)
polynomial_vector_l = lagrange(tmatrix_l)
polynomial_vector_r = lagrange(tmatrix_r)

with open("encrypted_witness.json", "r") as fi:
    witness_encdata = json.load(fi)
witness_e = [ECC.EccPoint(i[0],i[1]) for i in witness_encdata]

with open("encrypted_hG.json", "r") as fi:
    encrypted_hG = json.load(fi)
    hG = [ECC.EccPoint(i[0],i[1]) for i in encrypted_hG]


#random number you set
s = 3498503948

zs = calc_poly([GF(q-6),GF(11),GF(q-6),GF(1)],s)
hG_s = calc_poly(hG,s,True)

# zkproof = {"bG","L_T(s)","R(s)"}
s_o = calc_poly(give_witness(polynomial_vector_o,witness_e,True),s,True)
s_l = calc_poly(give_witness(polynomial_vector_l,witness_e,True),s,True)
n_r = get_R_s(s)

print("ZKP verify : ",s_l*num(n_r)+ -s_o==hG_s*num(zs))

### HACK THE INPUT2 