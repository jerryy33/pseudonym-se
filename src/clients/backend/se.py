"""Provides operations for searchable encryption schema on the client side"""
from typing import Any, List, Tuple
import pickle
from charm.toolbox.symcrypto import SymmetricCryptoAbstraction
from charm.toolbox.pairinggroup import ZR
import requests
from models import PseudonymRequest
from fastapi import HTTPException
from hashes import hs, h

from constants import GROUP, API_URL, MY_ID  # pylint: disable=no-name-in-module
from db import DB
from aliases import Document, Index  # pylint: disable=no-name-in-module
from util import generate_random_string, generate_wildcard_list


def gen_indizes(q_key: Any, keywords: List[str]) -> List[Index]:
    """Generates indices used for searchable encryption.
    Will send a request to the vault to compute a part for the encryption key

    Args:
        q_key (Any): a query key necassry to encrypt the index
        keyword (List[str]): a list of strings for which the indizes will be generated

    Returns:
        List[Index]: a list of indizes for the given keywords
    """
    index_requests = []
    # key = DB.hget(f"users:{MY_ID}", "seed")
    # seed=key.encode()
    for keyword in keywords:
        random_blind = GROUP.random(ZR)
        index_request = hs(GROUP, keyword) ** random_blind
        index_requests.append(
            GROUP.serialize(index_request, compression=False).decode()
        )
    response = requests.post(
        f"{API_URL}/generateIndex",
        json={"user_id": MY_ID, "hashed_keywords": index_requests},
        timeout=10,
    )
    if response.ok:
        index_answer = response.json()
    else:
        raise HTTPException(status_code=response.status_code, detail=response.json())
    indizes = []
    for index in index_answer:
        k = h(
            GROUP,
            GROUP.deserialize(index.encode(), compression=False)
            ** (q_key / random_blind),
        )
        print(k)
        index_encrypter = SymmetricCryptoAbstraction(k)
        res = generate_random_string(16)
        e_index = index_encrypter.encrypt(res)
        indizes.append((res, e_index))
    return indizes


def write(
    document: PseudonymRequest, encryption_key: bytes, enable_fuzzy_search: bool
) -> Document:
    """Generates a index and encrypts a document so that this tuple can be send to the vault

    Args:
        document (PseudonymRequest): a pseudonym request whoms data is written to the vault
        encryption_key (bytes): a symmetric key to encrypt data
        enable_fuzzy_search (bool): if fuzzy indizes should be created

    Returns:
        Document: a document containing the ciphertext and a matching index
    """
    keywords = list(document.data.values())
    query_key = DB.hget(f"users:{MY_ID}", "queryKey")
    i_w = []
    if enable_fuzzy_search:
        wildcard_lists = generate_wildcard_list(keywords)
        for wildcard_list in wildcard_lists:
            i_w.append(
                gen_indizes(GROUP.deserialize(query_key.encode()), wildcard_list)
            )
    else:
        i_w.append(gen_indizes(GROUP.deserialize(query_key.encode()), keywords))
    encoded_dict = pickle.dumps(document.data)
    record_encrypter = SymmetricCryptoAbstraction(encryption_key)
    cipher_text = record_encrypter.encrypt(encoded_dict)
    return (cipher_text, i_w)


def construct_query(q_key: Any, keywords: List[str]) -> Tuple[int, List[Any]]:
    """Constructs a valid query that is used for searching in the vault

    Args:
        q_key (Any): query key for constructing the query
        keyword (List[str]): keywords to search for

    Returns:
        Tuple[int, List[Any]]: a valid query containing the user id and a list of queries
    """
    queries = []
    # key = DB.hget(f"users:{MY_ID}", "seed")
    # seed=key.encode()
    for keyword in keywords:
        query = hs(GROUP, keyword) ** q_key
        queries.append(query)
    return (MY_ID, queries)
