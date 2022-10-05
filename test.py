from typing import List
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair, extract_key
import charm.core.crypto.AES as AES
from charm.core.math.pairing import ismember, pairing
import charm.toolbox.symcrypto as crypto
from hashlib import sha256
import ast

# important: .type for a paring element returns the hroup intger -> 0:ZR, 1:G1, 2:G2, 3:GT
database: List[tuple] = []
group1: PairingGroup
key: bytes
e: any
UA: List[int] = []
UR: List[int] = []
comKU: List[tuple] = []
def setup():
    # generate groups G1 and G2
    group1 = PairingGroup('SS512')

    #Generate encryption key e
    x = group1.random(G2)
    e = crypto.SymmetricCryptoAbstraction(extract_key(x))

    # extract x
    random = group1.random(ZR)
    # generate kum
    key= extract_key(random)
    #print(random, key)
    s= group1.random(GT)
    return key,random,group1, e, s, 
def enroll(k:bytes, u: int, x:tuple):
    xu = group1.random(ZR)
    g = group1.random(G1)
    comK = g ** (x / xu)
    #print(comK.type)

    comKU.append((comK,u))
    UA.append(u)
    return comK, (xu, s) ,g
def genIndex(qk:tuple, w: bytes, comK: tuple): #, g, random):
    random_blind = group1.random(ZR)
    index_request = (1,hs(None, w)**random_blind)

    index_answer = group1.pair_prod(index_request[1], comK)
    #print(group1.ismember((qk[0]/random_blind)))
    k = h(index_answer ** (qk[0]/random_blind)).digest()
   
    #print(index_answer ** (qk[0]/random_blind),
     #group1.pair_prod(hs(None,w), g)** random,
    # group1.pair_prod(hs(None,w)** qk[0], g ** (random/ qk[0])),
     # sep='\n \n', end='\n \n')
    #print((qk[0]/random_blind).type, comK.type,random_blind.type,index_request[1].type,index_answer.type, k)
    #print(index_answer ** (qk[0]/ random_blind))
    kv = crypto.SymmetricCryptoAbstraction(k)
    e_index = kv.encrypt(w)
    I_w = (w, e_index)

    return I_w, k
def write(e:crypto.SymmetricCryptoAbstraction, d:str): # g, random):
    I_w, k =  genIndex(qku, d.encode(), comK1)
    ct = e.encrypt(w.encode())
    #print(type(ct), ct)
    return (ct, I_w), k
def constructQ(qk: tuple, w:str):
    query = hs(None, w)** qk[0]
    #print(query.type)
    return (1, query)
def search(query: tuple):
    #print(comK1, comKU)
    if comK1 in comKU[0]:
        #print(group1.ismember(group1.pair_prod(query[1], comK1)))
        k1 = h(group1.pair_prod(query[1], comK1)).digest()
        #print(group1.pair_prod(query[1], comK1))
        aes = crypto.SymmetricCryptoAbstraction(k1)
        a = []
        for index in database:
            #print(index[1][1])
            e_index:str = index[1][1]
            #print(aes.decrypt(e_index), e_index)
            inn:bytes = aes.decrypt(e_index)
            print(inn, inn.decode())
            if index[1][0] == inn:
                a.append(index[0])

        return a
    else:
        return None   
def revoke(u:int):
    UA.remove(u)
    UR.append(u)
    #comKU.remove(u)
    #comKU.append((1, 333))
    entries = [item for item in comKU if item[1] == u]
    #print(entries)
    for entry in entries:
        if entry in comKU:
            comKU.remove(entry)


def hs(s, w: str):
    # TODO find out how to integrate s
    return group1.hash(w, type= G1)

def h(input):
    return sha256(group1.serialize(input, compression=False))

if __name__ == "__main__":
    #TODO handle word of any size now only multiple of 16
   w = 'word56789qwertzu'
   key, random, group1, e, s = setup()
   comK1, qku, g = enroll(key, 1, random)
   r, k = write(e, w)
   database.append(r)
   Q = constructQ(qku, w)
   a =  search(Q)
   #print(a)
   revoke(1)
   print(UR, UA, comKU)
