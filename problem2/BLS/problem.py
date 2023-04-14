from curve.curve import Point, CurvePoint, G1, G2, curve_order,BLS12_381_FQ,BLS12_381_FQ2
from curve.curve_fields import FQ, FQ2, FQ12, BLS12_381_FQ_MODULUS
from curve.pairing import *
from curve.fields import FQFac
import requests
import json

FQ3 = FQFac(52435875175126190479447740508185965837690552500527637822603658699938581184513)

hashmodn = 19
hashplus = 7
def make_weight(inp):
    return inp%hashmodn + hashplus

def keyGen():
    import random
    sk = random.randint(1,10*32)
    pk = G1*sk
    return pk,sk


# Alice's public key. Fake the multisig of yours and her address.
pk1 = BLS12_381_FQ(FQ(1181185806296752632974653716675246768098534223170321626248082366736700524754765164869821378404542376185982392116136), FQ(2012801563829391736645268852296875797885530049636233521036051260690583103087362625588475946831146650908068638178888))

# Message to sign
M_cordinate = [[1538499515549924581449960026291516693946849790953563699486744672675954712442361355383612696422401565701805654442174, 3313311951757304858487973524556456915266087719642958997514018023451551321637807338573441504685225602614056852911773], [2312039165878583006776367110661458113058883245950108314301346387916850917457971536517690401180973925145459051717800, 3711735669170592796153604814325359055332407507446576898361203169079351988708357512744345546830386307207309782045654]]
M = BLS12_381_FQ2(FQ2(M_cordinate[0]),FQ2(M_cordinate[1]))


#　This function is submitting the answer(faked signature) to the server and getting the private key of the NFT.
# sig is BLS12_381_FQ2 type (G2*n)
# pubkey is BLS12_381_FQ type (G1*n)
# The server side accept imput if pairing(G1,sig) = pairing(P,M)
# P = simplehash(alice_pubkey.x)*alice_pubkey + simplehash(bob_pubkey.x)*bob_pubkey
def send_signature(sig,pubkey):
    url = "https://problem2-k5lttve3hq-an.a.run.app/problem2"

    sendsig_ = [str(sig.x).split("u + "),str(sig.y).split("u + ")]
    sendsig = [[int(sendsig_[0][1]),int(sendsig_[0][0])],[int(sendsig_[1][1]),int(sendsig_[1][0])]]
    BLS12_381_FQ2(FQ2(sendsig[0]),FQ2(sendsig[1]))
    print("Wait for 20 sec")
    r = requests.post(url, data={'signature':json.dumps(sendsig),'publickey':json.dumps([pubkey.x.val,pubkey.y.val])})
    print(r.text)
    
