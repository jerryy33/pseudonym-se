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
    """Generates a index used for searchable encryption.
    Will send a request to the vault to compute a part for the encryption key

    Args:
        q_key (Any): a query key necassry to encrypt the index
        keyword (str): a string for which the index will be generated

    Returns:
        Index: a index for the keyword
    """
    index_requests = []
    for keyword in keywords:
        random_blind = GROUP.random(ZR)
        index_request = hs(GROUP, keyword) ** random_blind
        index_requests.append(
            GROUP.serialize(index_request, compression=False).decode()
        )
    # print(
    #     f"Sending index request {index_request} serialized as"
    #     f"{GROUP.serialize(index_request, compression= False)}"
    # )
    # TODO maybe shorten this to a single request
    response = requests.post(
        f"{API_URL}/generateIndex",
        json={"user_id": MY_ID, "hashed_keywords": index_requests},
        timeout=10,
    )
    if response.ok:
        index_answer = response.json()
    else:
        raise HTTPException(status_code=response.status_code, detail=response.json())
    # print(
    #     f"Received answer as {index_answer}, desiralized to"
    #     f"{GROUP.deserialize(index_answer.encode(), compression= False)}"
    # )
    # index_answer = GROUP.pair_prod(index_request[1], comp_key)
    # print(GROUP1.ismember((qk[0]/random_blind)))
    indizes = []
    for index in index_answer:
        k = h(
            GROUP,
            GROUP.deserialize(index.encode(), compression=False)
            ** (q_key / random_blind),
        )
        # print("Gen index key for enc", k)
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
        record_encrypter (SymmetricCryptoAbstraction): a symmetric encrypter
        document (str): a document to encrypt and send to the vault

    Returns:
        Document: a document conating the ciphertext and a matching index
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
    # print(type(ct), ct)
    return (cipher_text, i_w)


def construct_query(q_key: Any, keywords: List[str]) -> Tuple[int, List[Any]]:
    """Constructs a valid query that is used for searching in the vault

    Args:
        q_key (Any): query key for constructing the query
        keyword (str): a keyword to search for

    Returns:
        Tuple[int, Any]: a valid query containing the user id and a GROUP element
    """
    queries = []
    for keyword in keywords:
        query = hs(GROUP, keyword) ** q_key
        queries.append(query)
        # print(f"Constructed query as {query}")
    return (MY_ID, queries)
