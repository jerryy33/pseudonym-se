"""
A testfile to test the correctness of the SE-Scheme used for this project this includes all
functionality of the vault, the user-managament center and a single client.
Notes:
 - .type for a paring element returns the group integer -> 0:ZR, 1:G1, 2:G2, 3:GT
"""
from typing import Any, Dict, List, Tuple, Union
import pickle
import hmac
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
    keyed_hashed_object = hmac.digest(extract_key(s), w.encode(), sha256)
    return GROUP.hash(keyed_hashed_object, type=G1)


def h(element_to_hash: Any) -> bytes:
    return sha256(GROUP.serialize(element_to_hash, compression=False)).digest()


def generate_wildcard_list(words: Union[List, str]) -> List[List[str]]:
    # produces list of length n*2 +1 where n = len(word)
    if isinstance(words, str):
        words = [words]
        wildcard_list = [words]
    else:
        wildcard_list = []
    for word in words:
        keyword_wildcard_list = [word]
        for i in range(0, len(word) + 1):
            wildcard1 = word[:i] + "*" + word[i:]
            keyword_wildcard_list.append(wildcard1)
            if i == len(word):
                break
            wildcard2 = word[:i] + "*" + word[i + 1 :]
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


def enroll(u: int, x: Any, seed: Any):
    xu = GROUP.random(ZR)
    g = GROUP.random(G1)
    comp_key = g ** (x / xu)
    API_KEY_USER_ID_LIST.append((comp_key, u))
    UA.append(u)
    return comp_key, (xu, seed)


def revoke(u: int):
    UA.remove(u)
    UR.append(u)
    entries = [item for item in API_KEY_USER_ID_LIST if item[1] == u]
    for entry in entries:
        if entry in API_KEY_USER_ID_LIST:
            API_KEY_USER_ID_LIST.remove(entry)


def gen_index(qk: Any, comK: Any, word: str, s: Any):
    random_blind = GROUP.random(ZR)
    index_request = (1, hs(s, word) ** random_blind)

    index_answer = GROUP.pair_prod(index_request[1], comK)
    k = h(index_answer ** (qk[0] / random_blind))
    kv = SymmetricCryptoAbstraction(k)

    res = "".join(
        secrets.choice(string.ascii_uppercase + string.digits) for _ in range(16)
    )
    e_index = kv.encrypt(res)
    return (res, e_index)


def gen_indizes(
    qk: Any, keywords: List[str], comK: Any, s: Any
) -> List[Tuple[str, str]]:
    indices = []
    for word in keywords:
        i_w = gen_index(qk, comK, word, s)
        indices.append(i_w)
    return indices


def write(
    e: SymmetricCryptoAbstraction,
    query_key: Any,
    complementary_key: Any,
    s: Any,
    d: Dict,
    fuzzy: bool,
) -> bool:
    keywords = list(d["data"].values())
    if fuzzy:
        wildcard_lists = generate_wildcard_list(keywords)
        i_w = []
        for wildcard_keyword_list in wildcard_lists:
            i_w.append(
                gen_indizes(query_key, wildcard_keyword_list, complementary_key, s)
            )
    else:
        i_w = gen_indizes(query_key, keywords, complementary_key, s)
    encoded_dict = pickle.dumps(d["data"])
    ct = e.encrypt(encoded_dict)
    DB.append((ct, i_w))
    return True


def construct_query(qk: Any, w: List, s: Any) -> Tuple[int, List[Any]]:
    queries = []
    for word in w:
        query = hs(s, word) ** qk[0]
        queries.append(query)
    return (1, queries)


# more optimized for performance
def search_opt(queries: List[Any], complementary_key: Any):
    search_tokens = []
    for query in queries:
        search_tokens.append(h(GROUP.pair_prod(query, complementary_key)))
    results = []
    if complementary_key not in API_KEY_USER_ID_LIST[0]:
        return None
    for document, indices in DB:
        query_hits = 0
        for token in search_tokens:
            aes = SymmetricCryptoAbstraction(token)
            for index, enc_index in indices:
                inn: bytes = aes.decrypt(enc_index)
                if index == inn.decode(errors="replace"):
                    query_hits += 1
                    break
        if len(queries) == query_hits and query_hits > 0:
            results.append(document)
    return results


def search(queries: List[Any], complementary_key: Any):
    results = []
    if complementary_key not in API_KEY_USER_ID_LIST[0]:
        return None
    for document, indices in DB:
        query_hits = 0
        for query in queries:
            for index, enc_index in indices:
                k = h(GROUP.pair_prod(query, complementary_key))
                encrypter = SymmetricCryptoAbstraction(k)
                inn: bytes = encrypter.decrypt(enc_index)
                if index == inn.decode(errors="replace"):
                    query_hits += 1
                    break
        if len(queries) == query_hits and query_hits > 0:
            results.append(document)
    return results


def fuzzy_search(queries: List[List[str]], expected_amount_of_keywords: int = 1):
    if complementary_key not in API_KEY_USER_ID_LIST[0]:
        return None
    keys = []
    for q in queries:
        keys_per_keyword = []
        for token in q:
            keys_per_keyword.append(h(GROUP.pair_prod(token, complementary_key)))
        keys.append(keys_per_keyword)

    a = []
    for entry in DB:
        indices_lists = entry[1]
        query_hits = 0
        for keyword_index_list in indices_lists:
            for token_list_for_keyword in keys[:]:
                for index in keyword_index_list:
                    for key in token_list_for_keyword:
                        aes = SymmetricCryptoAbstraction(key)
                        e_index: str = index[1]
                        inn: bytes = aes.decrypt(e_index)
                        if index[0] == inn.decode(errors="replace"):
                            query_hits += 1
                            keys.remove(token_list_for_keyword)
                            break
                    else:
                        continue
                    break
                else:
                    continue
                break
        if query_hits > 0 and query_hits == expected_amount_of_keywords:
            a.append(entry[0])
    return a


if __name__ == "__main__":
    test_dict = {
        "keywords": ["name", "surname", "socialSecurityNumber"],
        "data": {
            "name": "Jeremy",
            "surname": "Herbst",
            "socialSecurityNumber": "1536363",
        },
    }
    # Exact Search Example
    UM_RANDOM, ENCRYPTER, SEED = setup()
    complementary_key, query_key = enroll(1, UM_RANDOM, SEED)
    write(ENCRYPTER, query_key, complementary_key, SEED, test_dict, False)
    _, q = construct_query(query_key, ["1536363", "Herbst"], SEED)
    search_results = search(q, complementary_key)
    for result in search_results:
        print(pickle.loads(ENCRYPTER.decrypt(result)))
    revoke(1)

    # Fuzzy Search Example
    # UM_RANDOM, ENCRYPTER, SEED = setup()
    # complementary_key, query_key = enroll(1, UM_RANDOM, SEED)
    # write(ENCRYPTER, query_key, complementary_key, test_dict, True)

    # search_words = ["1536363s", "Herbst"]
    # wildcard_lists = generate_wildcard_list(search_words)
    # queries_pro_keyword = []
    # for wildcard_list in wildcard_lists:
    #     user_id, queries = construct_query(query_key, wildcard_list)
    #     queries_pro_keyword.append(queries)
    # results = fuzzy_search(queries_pro_keyword, len(search_words))
    # for r in results:
    #     print(pickle.loads(ENCRYPTER.decrypt(r)))
