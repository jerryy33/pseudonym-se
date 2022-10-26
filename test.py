"""
A testfile to test the correctness of the SE-Scheme used for this project this includes all
functionality of the vault, the user-managament center and a single client.
Notes:
 - .type for a paring element returns the group integer -> 0:ZR, 1:G1, 2:G2, 3:GT
"""
from typing import Any, Dict, List, Tuple, Union
import time
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


def hs(s: Any, w: Any):
    # TODO find out how to integrate s
    return GROUP.hash(w, type=G1)


def h(element_to_hash: Any):
    return sha256(GROUP.serialize(element_to_hash, compression=False))


def generate_wildcard_list(words: Union[List, str]) -> List[List[str]]:
    # produces list of length n*2 +1 where n = len(word)
    if isinstance(words, str):
        words = [words]
        wildcard_list = [words]
    else:
        wildcard_list = []
    # print(words, wildcard_list)
    for word in words:
        # print(word)
        keyword_wildcard_list = [word]
        for i in range(0, len(word) + 1):
            wildcard1 = word[:i] + "*" + word[i:]
            # print("Wildcard1 is: ", wildcard1)
            keyword_wildcard_list.append(wildcard1)
            if i == len(word):
                break
            wildcard2 = word[:i] + "*" + word[i + 1 :]
            # print("Wildcard2 is: ", wildcard2)

            keyword_wildcard_list.append(wildcard2)
        wildcard_list.append(keyword_wildcard_list)
    return wildcard_list


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


def gen_index(qk: Any, comK: Any, word: str):
    random_blind = GROUP.random(ZR)
    index_request = (1, hs(None, word) ** random_blind)

    index_answer = GROUP.pair_prod(index_request[1], comK)
    # print(group1.ismember((qk[0]/random_blind)))
    k = h(index_answer ** (qk[0] / random_blind)).digest()
    # print(k)
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
    return (res, e_index)


def gen_indizes(qk: Any, keywords: List[str], comK: Any) -> List[Tuple[str, str]]:
    indices = []
    for word in keywords:
        i_w = gen_index(qk, comK, word)
        indices.append(i_w)
    return indices


def write(e: SymmetricCryptoAbstraction, d: Dict, fuzzy: bool):
    keywords = list(d["data"].values())
    # print(keywords)
    if fuzzy:
        wildcard_lists = generate_wildcard_list(keywords)
        i_w = []
        for wildcard_keyword_list in wildcard_lists:
            i_w.append(gen_indizes(query_key, wildcard_keyword_list, complementary_key))
    else:
        i_w = gen_indizes(query_key, keywords, complementary_key)
    encoded_dict = pickle.dumps(d["data"])
    ct = e.encrypt(encoded_dict)
    return (ct, i_w)


def construct_query(qk: Tuple[Any, Any], w: List) -> Tuple[int, List[Any]]:
    queries = []
    for word in w:
        query = hs(None, word) ** qk[0]
        queries.append(query)
    return (1, queries)


def search(queries: Tuple[int, List[Any]]):
    # print(comK1, comKU)
    results = []
    if complementary_key in API_KEY_USER_ID_LIST[0]:
        for entry in DB:
            # print(entry)
            query_hits = 0
            for query in queries[1]:
                k1 = h(GROUP.pair_prod(query, complementary_key)).digest()
                print(k1)
                # print(group1.pair_prod(query[1], comK1))
                aes = SymmetricCryptoAbstraction(k1)
                for index in entry[1]:
                    e_index: str = index[1]
                    # print(aes.decrypt(e_index), e_index)
                    inn: bytes = aes.decrypt(e_index)
                    # print(inn, inn.decode())
                    if index[0] == inn.decode(errors="replace"):
                        query_hits += 1
            print(len(queries[1]) == query_hits)
            if len(queries[1]) == query_hits and query_hits > 0:
                results.append(entry[0])

        return results
    return None


# TODO improve performance with breaks and return early (check if we can return after we have one result)
def fuzzy_search(
    user_id: int, queries: List[str], expected_amount_of_keywords: int = 1
):
    # print(comK1, comKU)
    if complementary_key in API_KEY_USER_ID_LIST[0]:
        keys = []
        for q in queries:
            keys.append(h(GROUP.pair_prod(q, complementary_key)).digest())
        a = []
        for entry in DB:
            indices_lists = entry[1]
            # print(entry)
            query_hits = 0
            for j, keyword_index_list in enumerate(indices_lists):
                for key in keys:
                    aes = SymmetricCryptoAbstraction(key)
                    for i, index in enumerate(keyword_index_list):
                        # print(i, j)
                        e_index: str = index[1]
                        # print(index[0], index[1])
                        inn: bytes = aes.decrypt(e_index)
                        # print(index[0])
                        if index[0] == inn.decode(errors="replace"):
                            query_hits += 1
                            # print(f"hit {query_hits}")
                            break
                    else:
                        continue
                    break
            print(
                query_hits,
                expected_amount_of_keywords,
                len(queries),
                len(keyword_index_list),
                len(indices_lists),
            )
            if query_hits > 0 and query_hits == expected_amount_of_keywords:
                a.append(entry[0])
        return a
    return None


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
    UM_RANDOM, ENCRYPTER, SEED = setup()
    complementary_key, query_key = enroll(1, UM_RANDOM)
    r = write(ENCRYPTER, test_dict, False)
    DB.append(r)
    # order is important needs to be same as keywords
    Q = construct_query(query_key, ["word123456789qwertz", "Herbst", "1536363"])
    search_results = search(Q)
    for result in search_results:
        print(pickle.loads(ENCRYPTER.decrypt(result)))
    revoke(1)

    # Fuzzy Search Example
    # UM_RANDOM, ENCRYPTER, SEED = setup()
    # complementary_key, query_key = enroll(1, UM_RANDOM)
    # r = write(ENCRYPTER, test_dict, True)
    # DB.append(r)
    # # order is important needs to be same as keywords
    # search_words = ["word123456789qwertz", "Herbst"]
    # wildcard_list = generate_wildcard_list(search_words)
    # wildcard_list = [item for sublist in wildcard_list for item in sublist]
    # user_id, queries = construct_query(query_key, wildcard_list)
    # start = time.time()
    # results = fuzzy_search(user_id, queries, len(search_words))
    # end = time.time()
    # print(end - start)
    # # print(results)
    # for r in results:
    #     print(pickle.loads(ENCRYPTER.decrypt(r)))
