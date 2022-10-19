"""Provides operations for searchable encryption schema on the client side"""
from typing import Any, List, Tuple
import pickle
from charm.toolbox.symcrypto import SymmetricCryptoAbstraction
from charm.toolbox.pairinggroup import ZR
import requests
from models import PseudonymRequest

from hashes import hs, h

from constants import GROUP, API_URL, MY_ID
from db import DB
from aliases import Document, Index
from util import generate_random_string


def gen_index(q_key: Any, keywords: List[str]) -> Index:
    """Generates a index used for searchable encryption.
    Will send a request to the vault to compute a part for the encryption key

    Args:
        q_key (Any): a query key necassry to encrypt the index
        keyword (str): a string for which the index will be generated

    Returns:
        Index: a index for the keyword
    """
    random_blind = GROUP.random(ZR)
    index_request = hs(GROUP, keywords) ** random_blind
    print(
        f"Sending index request {index_request} serialized as"
        f"{GROUP.serialize(index_request, compression= False)}"
    )
    index_answer = requests.get(
        f"{API_URL}/generateIndex",
        params={
            "user_id": MY_ID,
            "hashed_keyword": GROUP.serialize(index_request, compression=False),
        },
        timeout=10,
    ).json()
    print(
        f"Received answer as {index_answer}, desiralized to"
        f"{GROUP.deserialize(index_answer.encode(), compression= False)}"
    )
    # index_answer = GROUP.pair_prod(index_request[1], comp_key)
    # print(GROUP1.ismember((qk[0]/random_blind)))
    k = h(
        GROUP,
        GROUP.deserialize(index_answer.encode(), compression=False)
        ** (q_key / random_blind),
    )
    print("Gen index key for enc", k)
    index_encrypter = SymmetricCryptoAbstraction(k)
    res = generate_random_string(16)
    e_index = index_encrypter.encrypt(res)
    i_w = (res, e_index)
    return i_w


def write(document: PseudonymRequest, encryption_key: bytes) -> Document:
    """Generates a index and encrypts a document so that this tuple can be send to the vault

    Args:
        record_encrypter (SymmetricCryptoAbstraction): a symmetric encrypter
        document (str): a document to encrypt and send to the vault

    Returns:
        Document: a document conating the ciphertext and a matching index
    """
    keywords = [document.data[key] for key in document.keywords if key in document.data]
    query_key = DB.hget(f"users:{MY_ID}", "queryKey")
    i_w = gen_index(GROUP.deserialize(query_key.encode()), keywords)
    encoded_dict = pickle.dumps(document.data)
    record_encrypter = SymmetricCryptoAbstraction(encryption_key)
    cipher_text = record_encrypter.encrypt(encoded_dict)
    # print(type(ct), ct)
    return (cipher_text, i_w)


def construct_query(q_key: Any, keywords: List[str]) -> Tuple[int, Any]:
    """Constructs a valid query that is used for searching in the vault

    Args:
        q_key (Any): query key for constructing the query
        keyword (str): a keyword to search for

    Returns:
        Tuple[int, Any]: a valid query containing the user id and a GROUP element
    """
    query = hs(GROUP, keywords) ** q_key
    print(f"Constructed query as {query}")
    return (MY_ID, query)
