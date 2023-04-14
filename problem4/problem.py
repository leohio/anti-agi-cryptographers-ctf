import numpy as np
from Crypto.PublicKey import ECC
from copy import deepcopy
from fielddef import FQFac
from virtualFHE import *
from qap import *
import requests
import json

q = 115792089210356248762697446949407573529996955224135760342422259061068512044369
GF = FQFac(q)
G = ECC.construct(d=1,curve='secp256r1').pointQ
ZERO = G+-G

modq = 17064117955711778576537207979155607882504061569450183867868045703

###
# IMPORTANT: IT'S ALMOST THE SAME CIRCUIT OF PROBLEM3
# IF YOU TRY THE MOVE OF CORRECT INPUTS, TRY THAT ON problem3/qap_test.py
###

input1 = 0 #Your input. Change it.
input2 = input1**2
input3 = input2//modq
modres = 13536286123957158454762356702261335574349940617021644221111543876
input4 = input2 - modres

gate1 = [["c2"],["c1"],["c1"]]
gate2 = [["c4"],["c3"],[str(modq)]]
gate3 = [["c2"],["c4",str(modres)],[]]

gates = [gate1,gate2,gate3]
gmatrix = gates2LRO(gates)
# O = L*R

tmatrix_o = np.array(gmatrix["O"]).T
tmatrix_l = np.array(gmatrix["L"]).T
tmatrix_r = np.array(gmatrix["R"]).T

polynomial_vector_o = lagrange(tmatrix_o)
polynomial_vector_l = lagrange(tmatrix_l)
polynomial_vector_r = lagrange(tmatrix_r)

with open("we_publickey.json","r") as fi:
    we_publickey = json.load(fi)

witness = [GF(1),GF(input1),GF(input2),GF(input3),GF(input4)]


""" DECRYPTION OF Witness Encryption"""
to_send = []
for i in range(64):
    final_polyvec_o = give_witness_enc(we_publickey[i]["O"],witness)
    final_polyvec_l = give_witness_enc(we_publickey[i]["L"],witness) 
    final_polyvec_r = give_witness(polynomial_vector_r,witness)

    total = VirtualFHECiphertext([])
    
    for i in (1,2,3):
        o_ = calc_poly_enc(final_polyvec_o,i)
        l_ = calc_poly_enc(final_polyvec_l,i)
        r_= calc_poly(final_polyvec_r,i).val

        total += l_*r_ + o_*-1
        
    to_send.append(total.lst)


### you can send an array of ciphertext
### returns the array of bool. Each bool means that each ciphertext is zero.
### For example, [Ciphertext, CipherText, Ciphertext] => [True, False, True]
def oracle_equal_zero(to_send):

    problem4 = "ec2-18-183-196-9.ap-northeast-1.compute.amazonaws.com"
    r = requests.post('https://problem4-k5lttve3hq-an.a.run.app/problem4', data={'ciphertext':json.dumps(to_send)})
    print(r)
    retd = json.loads(r.text)
    return retd

### This Witness Encryption(we)'s  private key is [Bool]*64 
### The array of all False or all True is a failure
we_privatekey = oracle_equal_zero(to_send)
print(we_privatekey)
print("if you get the private key, format it with boolArray2number()")

def boolArray2number(we_privkey):
    ret = 0
    for i in range(len(we_privkey)):
        ret += 8**i*we_privkey[i]
    return ret

print(boolArray2number(we_privatekey))