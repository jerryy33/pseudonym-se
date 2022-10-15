"""
A testfile to test the correctness of the SE-Scheme used for this project this includes all
functionality of the vault, the user-managament center and a single client.
"""

from typing import Any, Dict, List, Tuple
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, extract_key  # type: ignore
from charm.toolbox.symcrypto import SymmetricCryptoAbstraction
from hashlib import sha256
import pickle
import secrets
import string

# important: .type for a paring element returns the group integer -> 0:ZR, 1:G1, 2:G2, 3:GT
database: List[tuple] = []
group1: PairingGroup
key: bytes
e: SymmetricCryptoAbstraction
UA: List[int] = []
UR: List[int] = []
comKU: List[tuple] = []


def setup():
    # generate groups G1 and G2
    group1 = PairingGroup("SS512")

    # Generate encryption key e
    x = group1.random(G2)
    # print(type(x), x)
    e = SymmetricCryptoAbstraction(extract_key(x))

    # extract x
    random = group1.random(ZR)
    # generate kum
    key = extract_key(random)
    # print(random, key)
    s = group1.random(GT)
    return (
        key,
        random,
        group1,
        e,
        s,
    )


def enroll(u: int, x: Any):
    xu = group1.random(ZR)
    # print(xu)
    g = group1.random(G1)
    comK = g ** (x / xu)
    # print(comK.type)
    # print(f"Sending comp key{comK} to serv")
    comKU.append((comK, u))
    UA.append(u)
    return comK, (xu, s)


def revoke(u: int):
    UA.remove(u)
    UR.append(u)
    # comKU.remove(u)
    # comKU.append((1, 333))
    entries = [item for item in comKU if item[1] == u]
    # print(entries)
    for entry in entries:
        if entry in comKU:
            comKU.remove(entry)


def genIndex(qk: Tuple[Any, Any], w: List[str], comK: Any):  # , g, random):
    random_blind = group1.random(ZR)
    index_request = (1, hs(None, w) ** random_blind)

    index_answer = group1.pair_prod(index_request[1], comK)
    # print(group1.ismember((qk[0]/random_blind)))
    k = h(index_answer ** (qk[0] / random_blind)).digest()
    print(k)
    # print(index_answer ** (qk[0]/random_blind),
    # group1.pair_prod(hs(None,w), g)** random,
    # group1.pair_prod(hs(None,w)** qk[0], g ** (random/ qk[0])),
    # sep='\n \n', end='\n \n')
    # print((qk[0]/random_blind).type, comK.type,random_blind.type,index_request[1].type,index_answer.type, k)
    # print(index_answer ** (qk[0]/ random_blind))
    kv = SymmetricCryptoAbstraction(k)

    res = "".join(
        secrets.choice(string.ascii_uppercase + string.digits) for i in range(16)
    )
    e_index = kv.encrypt(res)
    I_w = (res, e_index)

    return I_w


def write(e: SymmetricCryptoAbstraction, d: Dict):
    keywords = [d["data"][key] for key in d["keywords"] if key in d["data"]]
    print(keywords)
    I_w = genIndex(qku, keywords, comK1)
    encoded_dict = pickle.dumps(d["data"])
    ct = e.encrypt(encoded_dict)
    return (ct, I_w)


def construct_query(qk: Tuple[Any, Any], w: List):
    query = hs(None, w) ** qk[0]
    return (1, query)


def search(query: Tuple[int, Any]):
    # print(comK1, comKU)
    if comK1 in comKU[0]:

        k1 = h(group1.pair_prod(query[1], comK1)).digest()
        print(k1)
        # print(group1.pair_prod(query[1], comK1))
        aes = SymmetricCryptoAbstraction(k1)
        a = []
        for index in database:
            # print(index[1][1])
            e_index: str = index[1][1]
            # print(aes.decrypt(e_index), e_index)
            inn: bytes = aes.decrypt(e_index)
            # print(inn, inn.decode())
            if index[1][0] == inn.decode(errors="replace"):
                a.append(index[0])

        return a
    return None


def hs(s: Any, w: Any):
    # TODO find out how to integrate s
    return group1.hash(w, type=G1)


def h(input: Any):
    return sha256(group1.serialize(input, compression=False))


if __name__ == "__main__":
    test_dict = {
        "keywords": ["name", "surname", "socialSecurityNumber"],
        "data": {
            "name": "word123456789qwertz",
            "surname": "Herbst",
            "socialSecurityNumber": "1536363",
        },
    }
    key, random, group1, e, s = setup()
    comK1, qku = enroll(1, random)
    r = write(e, test_dict)
    database.append(r)
    # order is important needs to be same as keywords
    Q = construct_query(qku, ["word123456789qwertz", "Herbst", "1536363"])
    a = search(Q)
    print(a[0])
    print(pickle.loads(e.decrypt(a[0])))
    revoke(1)
    # print(UR, UA, comKU)
