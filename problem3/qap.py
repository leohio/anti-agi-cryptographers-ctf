
### FOR CTF PPL: There is NO volunerabitlity in this file.

from Crypto.PublicKey import ECC
from copy import deepcopy
from fielddef import FQFac

q = 115792089210356248762697446949407573529996955224135760342422259061068512044369
GF = FQFac(q)

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

#only for 3D poly
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

def give_witness(vecs,witness,enc=False):
    if len(vecs)!=len(witness):
        print("Error: matrix format is incorrect")
        return False
    
    ret = [GF(0),GF(0),GF(0)]
    if enc:
        ret = [G+-G,G+-G,G+-G]

    for i in range(len(vecs)):
        
        if len(vecs[i])!=len(ret):
            return False
        for j in range(len(vecs[i])):
            ret[j] += witness[i]*num(vecs[i][j])

    return ret

def num(x):
    if type(x)==int:
        return x
    else:
        return x.val

def calc_poly(polyvec,x,enc=False):
    ret = GF(0)
    if enc:
        ret = G+-G
    for i in range(len(polyvec)):
        ret = polyvec[i]*num(x**i) + ret

    return ret

def polyadd(x,y,sub_flag=False):
    diff = len(x)-len(y)
    if diff>0:
        y+= [GF(0)]*diff
    else: 
        x+= [GF(0)]*(-diff)
    if sub_flag:
        return [x_-y_ for (x_, y_) in zip(x, y)]
    return [x_+y_ for (x_, y_) in zip(x, y)]

def polymul2Dx2D(x, y):
    return [x[0]*y[0], x[1]*y[0]+x[0]*y[1],x[0]*y[2]+y[0]*x[2]+x[1]*y[1],x[1]*y[2]+x[2]*y[1],x[2]*y[2]]

def polydiv(g,xs_, ys_):
    xs = deepcopy(xs_);ys =deepcopy(ys_)
    xs.reverse()
    ys.reverse()
    xn = len(xs)
    yn = len(ys)
    zs = xs.copy()
    qs = []
    for i in range(xn - yn + 1):
        temp = (zs[0] / ys[0])
        for j in range(yn):
            zs[j] -= temp * ys[j]
        qs.append(temp)
        zs = zs[1:]
    if qs == []: qs = [GF(0)]
    for i in zs:
        if i!=GF(0):
            print("Error: div failed")
            return False
    qs.reverse()
    return qs

def get_R_s(s):
    import requests
    import json
    r = requests.post('https://problem3-k5lttve3hq-an.a.run.app/problem3', data={'s':s})
    return json.loads(r.text)