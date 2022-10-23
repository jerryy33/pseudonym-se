"""
A testfile to test the correctness of the SE-Scheme used for this project this includes all
functionality of the vault, the user-managament center and a single client.
Notes:
 - .type for a paring element returns the group integer -> 0:ZR, 1:G1, 2:G2, 3:GT
"""
from typing import Any, Dict, List, Tuple
import pickle
import secrets
import string
from hashlib import sha256
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, extract_key
from charm.toolbox.symcrypto import SymmetricCryptoAbstraction


DB: List[Tuple] = []
GROUP = PairingGroup("SS512")
ENCRYPTER: SymmetricCryptoAbstraction
SEED: Any
UM_RANDOM: Any
UA: List[int] = []
UR: List[int] = []
API_KEY_USER_ID_LIST: List[Tuple[int, str]] = []


def setup():
    # Generate encryption key e
    x = GROUP.random(G2)
    #  encryption key used for document encryption/decryption
    enc_key = SymmetricCryptoAbstraction(extract_key(x))

    # random group element for user manager
    um_random = GROUP.random(ZR)

    # random seed for clients
    s = GROUP.random(GT)
    return (
        um_random,
        enc_key,
        s,
    )


def enroll(u: int, x: Any):
    xu = GROUP.random(ZR)
    # print(xu)
    g = GROUP.random(G1)
    comp_key = g ** (x / xu)
    # print(comK.type)
    # print(f"Sending comp key{comK} to serv")
    API_KEY_USER_ID_LIST.append((comp_key, u))
    UA.append(u)
    return comp_key, (xu, SEED)


def revoke(u: int):
    UA.remove(u)
    UR.append(u)
    # comKU.remove(u)
    # comKU.append((1, 333))
    entries = [item for item in API_KEY_USER_ID_LIST if item[1] == u]
    # print(entries)
    for entry in entries:
        if entry in API_KEY_USER_ID_LIST:
            API_KEY_USER_ID_LIST.remove(entry)


def gen_index(qk: Tuple[Any, Any], w: List[str], comK: Any):  # , g, random):
    random_blind = GROUP.random(ZR)
    index_request = (1, hs(None, w) ** random_blind)

    index_answer = GROUP.pair_prod(index_request[1], comK)
    # print(group1.ismember((qk[0]/random_blind)))
    k = h(index_answer ** (qk[0] / random_blind)).digest()
    print(k)
    # print(index_answer ** (qk[0]/random_blind),
    # group1.pair_prod(hs(None,w), g)** random,
    # group1.pair_prod(hs(None,w)** qk[0], g ** (random/ qk[0])),
    # sep='\n \n', end='\n \n')
    # print((qk[0]/random_blind).type, comK.type,random_blind.type,
    # index_request[1].type,index_answer.type, k)
    # print(index_answer ** (qk[0]/ random_blind))
    kv = SymmetricCryptoAbstraction(k)

    res = "".join(
        secrets.choice(string.ascii_uppercase + string.digits) for _ in range(16)
    )
    e_index = kv.encrypt(res)
    i_w = (res, e_index)

    return i_w


def write(e: SymmetricCryptoAbstraction, d: Dict):
    keywords = [d["data"][key] for key in d["keywords"] if key in d["data"]]
    print(keywords)
    I_w = gen_index(query_key, keywords, complementary_key)
    encoded_dict = pickle.dumps(d["data"])
    ct = e.encrypt(encoded_dict)
    return (ct, I_w)


def construct_query(qk: Tuple[Any, Any], w: List):
    query = hs(None, w) ** qk[0]
    return (1, query)


def search(query: Tuple[int, Any]):
    # print(comK1, comKU)
    if complementary_key in API_KEY_USER_ID_LIST[0]:

        k1 = h(GROUP.pair_prod(query[1], complementary_key)).digest()
        print(k1)
        # print(group1.pair_prod(query[1], comK1))
        aes = SymmetricCryptoAbstraction(k1)
        a = []
        for index in DB:
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
    return GROUP.hash(w, type=G1)


def h(element_to_hash: Any):
    return sha256(GROUP.serialize(element_to_hash, compression=False))


# TODO improve performance with breaks and return early (check if we can return after we have one result)
def fuzzy_search(query: Tuple[int, Any]):
    # print(comK1, comKU)
    if complementary_key in API_KEY_USER_ID_LIST[0]:
        queries_list = query[1]
        a = []
        for q in queries_list:
            k1 = h(GROUP.pair_prod(q, complementary_key)).digest()
            # print(k1)
            # print(group1.pair_prod(query[1], comK1))
            aes = SymmetricCryptoAbstraction(k1)
            for entry in DB:
                indices_list = entry[1]
                for index in indices_list:
                    e_index: str = index[1]
                    # print(index[0], index[1])
                    inn: bytes = aes.decrypt(e_index)
                    # print(index[0])
                    if index[0] == inn.decode(errors="replace"):
                        a.append(entry[0])

        return a
    return None


def gen_indizes_for_fuzzy(
    qk: Tuple[Any, Any], w: List[str], comK: Any
):  # , g, random):
    wildcard_list = generate_wildcard_list(w[0])
    list_of_indices = []
    for wildcard in wildcard_list:
        random_blind = GROUP.random(ZR)
        index_request = (1, hs(None, wildcard) ** random_blind)

        index_answer = GROUP.pair_prod(index_request[1], comK)
        # print(group1.ismember((qk[0]/random_blind)))
        k = h(index_answer ** (qk[0] / random_blind)).digest()
        # print(k)
        # print(index_answer ** (qk[0]/random_blind),
        # group1.pair_prod(hs(None,w), g)** random,
        # group1.pair_prod(hs(None,w)** qk[0], g ** (random/ qk[0])),
        # sep='\n \n', end='\n \n')
        # print((qk[0]/random_blind).type, comK.type,random_blind.type,index_request[1].type,index_answer.type, k)
        # print(index_answer ** (qk[0]/ random_blind))
        kv = SymmetricCryptoAbstraction(k)

        res = "".join(
            secrets.choice(string.ascii_uppercase + string.digits) for _ in range(16)
        )
        e_index = kv.encrypt(res)
        i_w = (res, e_index)
        list_of_indices.append(i_w)

    return list_of_indices


def write_for_fuzzy(e: SymmetricCryptoAbstraction, d: Dict):
    keywords = [d["data"][key] for key in d["keywords"] if key in d["data"]]
    # print(keywords)
    I_w = gen_indizes_for_fuzzy(query_key, keywords, complementary_key)
    encoded_dict = pickle.dumps(d["data"])
    ct = e.encrypt(encoded_dict)
    return (ct, I_w)


def construct_queries_fuzzy(qk: Tuple[Any, Any], w: List):
    wildcard_list = generate_wildcard_list(w[0])
    queries = []
    for wildcard in wildcard_list:
        query = hs(None, wildcard) ** qk[0]
        queries.append(query)
    return (1, queries)


def generate_wildcard_list(word: str) -> List:
    # produces list of length n*2 +1 where n = len(word)
    wildcard_list = [word]
    for i in range(0, len(word) + 1):
        wildcard1 = word[:i] + "*" + word[i:]
        print("Wildcard1 is: ", wildcard1)
        wildcard_list.append(wildcard1)
        if i == len(word):
            break
        wildcard2 = word[:i] + "*" + word[i + 1 :]
        print("Wildcard2 is: ", wildcard2)

        wildcard_list.append(wildcard2)

    return wildcard_list


if __name__ == "__main__":
    test_dict = {
        "keywords": ["name", "surname", "socialSecurityNumber"],
        "data": {
            "name": "word123456789qwertz",
            "surname": "Herbst",
            "socialSecurityNumber": "1536363",
        },
    }
    # Exact Search Example
    # UM_RANDOM, ENCRYPTER, SEED = setup()
    # complementary_key, query_key = enroll(1, UM_RANDOM)
    # r = write(ENCRYPTER, test_dict)
    # DB.append(r)
    # # order is important needs to be same as keywords
    # Q = construct_query(query_key, ["word123456789qwertz", "Herbst", "1536363"])
    # search_results = search(Q)
    # print(pickle.loads(ENCRYPTER.decrypt(search_results[0])))
    # revoke(1)

    # Fuzzy Search Example
    UM_RANDOM, ENCRYPTER, SEED = setup()
    complementary_key, query_key = enroll(1, UM_RANDOM)
    r = write_for_fuzzy(ENCRYPTER, test_dict)
    DB.append(r)
    # order is important needs to be same as keywords
    Q = construct_queries_fuzzy(query_key, ["word123456789qwertz"])
    results = fuzzy_search(Q)
    for r in results:
        print(pickle.loads(ENCRYPTER.decrypt(r)))
