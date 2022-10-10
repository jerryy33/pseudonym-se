from typing import Tuple, Any, List
import string
import secrets
import requests
from charm.toolbox.pairinggroup import PairingGroup, ZR  # type: ignore
from charm.toolbox.symcrypto import SymmetricCryptoAbstraction
from hashes import hs, h


Index = Tuple[str, str]
Document = Tuple[str, Index]
MY_ID = 1
API_URL = "http://localhost:8000"
UM_URL = "http://localhost:8080"
group = PairingGroup("SS512")
values = requests.post(f"{UM_URL}/enroll/{MY_ID}", timeout=10).json()
# print(values["groupElement"])
query_key = group.deserialize(values["groupElement"].encode(), compression=False)
# print(query_key)
seed = group.deserialize(values["seed"].encode(), compression=False)
encryption_key: bytes = values["encKey"]
encrypter = SymmetricCryptoAbstraction(encryption_key)


def add_record(record: str) -> bool:
    """Add an encrypted record to the vault

    Args:
        record (str): a encrypted record

    Returns:
        bool: true if adding the record was successfull
    """
    document = write(encrypter, record)
    index = document[1]
    # print(document)
    return requests.post(
        f"{API_URL}/addRecord",
        params={"record": document[0], "index1": index[0], "index2": index[1]},
        timeout=10,
    ).json()


def search_for_record(record: str) -> List:
    """Searches for records in the vault and returns them if they match the search record

    Args:
        record (str): a record to search for

    Returns:
        List: a list of matching records
    """
    query = construct_query(query_key, record)
    return requests.get(
        f"{API_URL}/search",
        params={
            "user_id": query[0],
            "query": group.serialize(query[1], compression=False),
        },
        timeout=10,
    ).json()


def gen_index(q_key: Any, keyword: str) -> Index:
    """Generates a index used for searchable encryption.
    Will send a request to the vault to compute a part for the encryption key

    Args:
        q_key (Any): a query key necassry to encrypt the index
        keyword (str): a string for which the index will be generated

    Returns:
        Index: a index for the keyword
    """
    random_blind = group.random(ZR)
    index_request = hs(group, keyword) ** random_blind
    print(
        f"Sending index request {index_request} serialized as {group.serialize(index_request, compression= False)}"
    )
    index_answer = requests.get(
        f"{API_URL}/generateIndex",
        params={
            "user_id": MY_ID,
            "hashed_keyword": group.serialize(index_request, compression=False),
        },
        timeout=10,
    ).json()
    print(
        f"Received answer as {index_answer}, desiralized to {group.deserialize(index_answer.encode(), compression= False)}"
    )
    # index_answer = group.pair_prod(index_request[1], comp_key)
    # print(group1.ismember((qk[0]/random_blind)))
    k = h(
        group,
        group.deserialize(index_answer.encode(), compression=False)
        ** (q_key / random_blind),
    )
    print("Gen index key for enc", k)
    # print(index_answer ** (qk[0]/random_blind),
    # group1.pair_prod(hs(None,w), g)** random,
    # group1.pair_prod(hs(None,w)** qk[0], g ** (random/ qk[0])),
    # sep='\n \n', end='\n \n')
    # print((qk[0]/random_blind).type, comK.type,random_blind.type,index_request[1].type,index_answer.type, k)
    # print(index_answer ** (qk[0]/ random_blind))
    index_encrypter = SymmetricCryptoAbstraction(k)
    res = "".join(
        secrets.choice(string.ascii_uppercase + string.digits) for i in range(16)
    )
    e_index = index_encrypter.encrypt(res)
    i_w = (res, e_index)
    # print(i_w)

    return i_w


def write(record_encrypter: SymmetricCryptoAbstraction, document: str) -> Document:
    """Generates a index and encrypts a document so that this tuple can be send to the vault

    Args:
        record_encrypter (SymmetricCryptoAbstraction): a symmetric encrypter
        document (str): a document to encrypt and send to the vault

    Returns:
        Document: a document conating the ciphertext and a matching index
    """
    i_w = gen_index(query_key, document)
    cipher_text = record_encrypter.encrypt(document)
    # print(type(ct), ct)
    return (cipher_text, i_w)


def construct_query(q_key: Any, keyword: str) -> Tuple[int, Any]:
    """Constructs a valid query that is used for searching in the vault

    Args:
        q_key (Any): query key for constructing the query
        keyword (str): a keyword to search for

    Returns:
        Tuple[int, Any]: a valid query containing the user id and a group element
    """
    query = hs(group, keyword) ** q_key
    print(f"Constructed query as {query}")
    return (MY_ID, query)


def generate_random_string(length: int) -> str:
    """Generate a random string for a given length.
    Contains digits and uppercase letters only


    Args:
        len (int): length of the generated random string

    Returns:
        str: random string
    """
    return "".join(
        secrets.choice(string.ascii_uppercase + string.digits) for i in range(length)
    )


if __name__ == "__main__":
    test_word = "word56789qwertzu"
    result = add_record(test_word)
    print(result)
    search_results = search_for_record(test_word)
    print(search_results)
    decoded_words = [encrypter.decrypt(word).decode() for word in search_results]
    print(decoded_words)
    revoke: bool = requests.post(
        f"{UM_URL}/revoke", params={"user_id": MY_ID}, timeout=10
    ).json()
    print(revoke)
    # should return no records
    d = search_for_record(test_word)
    print(d)
