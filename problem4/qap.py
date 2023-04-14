### FOR CTF PPL: There is NO volunerabitlity in this file.

from Crypto.PublicKey import ECC
from copy import deepcopy
from fielddef import FQFac
from virtualFHE import *

q = 115792089210356248762697446949407573529996955224135760342422259061068512044369
GF = FQFac(q)
G = ECC.construct(d=1,curve='secp256r1').pointQ
ZERO = G+-G

# O = L*R
def gates2LRO(gates):
    gmatrix = {"O":[],"L":[],"R":[]}

    for gate in gates:
        o_array = [0,0,0,0,0]
        for o in gate[0]:
            o_array = [0,0,0,0,0]
            if "c" not in o:
                o_array[0] = int(o)
            else:
                num = int(o[1:])
                o_array[num] = 1
        gmatrix["O"].append(o_array)

        l_array = [0,0,0,0,0]
        for l in gate[1]:
            if "c" not in l:
                l_array[0] = int(l)
            else:
                num = int(l[1:])
                l_array[num] = 1
        gmatrix["L"].append(l_array)

        r_array = [0,0,0,0,0]
        for r in gate[2]:
            if "c" not in r:
                r_array[0] = int(r)
            else:
                num = int(r[1:])
                r_array[num] = 1
        if len(gate[2])==0:
            r_array[0]=1
        gmatrix["R"].append(r_array)

    return gmatrix


def lagrange(matrix):
    ret = []
    for lst in matrix:
        x0,x1,x2=GF(0),GF(0),GF(0)
        x0 += GF(lst[0])/GF(2)
        x1 -= GF(lst[0])*GF(5)/GF(2)
        x2 += GF(lst[0])*GF(3)

        x0 -= GF(lst[1])
        x1 += GF(lst[1])*GF(4)
        x2 -= GF(lst[1])*GF(3)

        x0 += GF(lst[2])/GF(2)
        x1 -= GF(lst[2])*GF(3)/GF(2)
        x2 += GF(lst[2])
        ret.append((x2,x1,x0))

    return ret

def give_witness(vecs,witness):
    if len(vecs)!=len(witness):
        print("Error: matrix format is incorrect")
        return False
    
    ret = [GF(0),GF(0),GF(0)]

    for i in range(len(vecs)):
        
        if len(vecs[i])!=len(ret):
            return False
        for j in range(len(vecs[i])):
            ret[j] += vecs[i][j] * witness[i].val

    return ret

def give_witness_enc(vecs,witness):
    if len(vecs)!=len(witness):
        print("Error: matrix format is incorrect")
        return False
    
    ret = [VirtualFHECiphertext([]),VirtualFHECiphertext([]),VirtualFHECiphertext([])]

    for i in range(len(vecs)):
        
        if len(vecs[i])!=len(ret):
            return False
        for j in range(len(vecs[i])):
            ret[j] += VirtualFHECiphertext(vecs[i][j]) * witness[i].val

    return ret

def num(x):
    if type(x)==int:
        return x
    else:
        return x.val

def calc_poly(polyvec,x):
    ret = GF(0)
    for i in range(len(polyvec)):
        ret = ret + polyvec[i]*num(x**i)

    return ret

def calc_poly_enc(polyvec,x):
    
    ret =  VirtualFHECiphertext([])
    for i in range(len(polyvec)):
        ret = ret + VirtualFHECiphertext(polyvec[i].lst)*num(x**i)

    return ret

def encrypt_lagrange(matrix,key,masterkey,randam=False):
    from cryptography.fernet import Fernet
    import random
    masterf = Fernet(masterkey)
    tag = masterf.encrypt(key)
    #inskeys.append(tag.decode('utf-8'))
    f = Fernet(key)
    ret = []
    for line in matrix:
        instant_line = []
        for i in  line:
            if randam==False:
                bi = int.to_bytes(i.val,32,"little")
            else:
                if i.val not in (0,1):
                    bi = int.to_bytes(random.randint(0,q-1),32,"little")
                else:
                    bi = int.to_bytes(i.val,32,"little")
            token = f.encrypt(bi)
            ct = [VirtualFHECiphertextUnit(token,tag,1,1)]
            instant_line.append(ct)
        ret.append(instant_line)
    return ret