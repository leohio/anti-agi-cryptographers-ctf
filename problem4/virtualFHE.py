
### FOR CTF PPL: There is NO volunerabitlity in this file.

from copy import deepcopy
from cryptography.fernet import Fernet

def VirtualFHECiphertextUnit(ciphertext,tag,scalar,sign=1):

    ret = {
        "ciphertext":ciphertext.decode("utf-8"),
        "tag": tag.decode("utf-8"),
        "scalar":scalar,
        "sign":sign
    }
    return ret


class VirtualFHECiphertext(object):
    
    def __init__(self,lst):
        self.lst = lst
        if type(lst) != list:
            raise 

    def __add__(self,other):
        return VirtualFHECiphertext(deepcopy(self.lst) + deepcopy(other.lst))
        

    def __mul__(self,other):
        copied = deepcopy(self.lst)
        for i in copied:
            i["scalar"] = i["scalar"] * other
        return VirtualFHECiphertext(copied)

    def decrypt(self,key):
        ret  = 0
        f = Fernet(key)
        for i in self.lst:
            inskey = f.decrypt(i["tag"].encode("utf-8"))
            insf = Fernet(inskey)
            number  = int.from_bytes(insf.decrypt(i["ciphertext"].encode("utf-8")),"little")
            ret += number*i["scalar"]*i["sign"]

        return ret


