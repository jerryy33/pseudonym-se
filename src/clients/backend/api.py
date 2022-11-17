"""This module represent a data client that can request pseudonyms from a server"""
from typing import Dict, List, Tuple
import pickle
import requests
from charm.toolbox.symcrypto import SymmetricCryptoAbstraction
from charm.toolbox.pairinggroup import extract_key
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from util import generate_wildcard_list

from models import PseudonymRequest, SecurityDetails
from constants import GROUP, API_URL, MY_ID  # pylint: disable=no-name-in-module
from se import write, construct_query
from db import DB

app = FastAPI()
origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.put("/receiveSecurityDetails")
def receive_security_details(details: SecurityDetails) -> int:
    """Endpoint to receive security details

    Args:
        details (SecurityDetails): security details containing a query key,
        a random seed and an encryption key

    Raises:
        HTTPException: if the received user_id doesnt equal own id

    Returns:
        int: added fields to the database
    """
    if details.user_id != MY_ID:
        raise HTTPException(
            status_code=400,
            detail="Security Details were not meant to be for this user",
        )
    added_fields = DB.hset(
        f"users:{MY_ID}",
        mapping={
            "queryKey": details.query_key,
            "seed": f"{extract_key(GROUP.deserialize(details.seed, compression=False))}",
            "encryptionKey": details.encryption_key,
        },
    )
    # print(added_fields)
    return added_fields


@app.post("/requestPseudonym")
def request_pseudonym(record: PseudonymRequest) -> List[Tuple[Dict, str]]:
    """Requests a pseudonym for a given data record, if no entry on the server is found
    adds a new encrypted record to the server. If multiple records match, the user can choose the one
    thats actually correct

    Args:
        record (PseudonymRequest): a given data record

    Returns:
        List[Tuple[Dict, str]]: a list containing pseudonyms and the matching record
    """
    # print(record)
    key: str = DB.hget(f"users:{MY_ID}", "encryptionKey")
    if key is None:
        raise HTTPException(status_code=400, detail="User has not been enrolled yet")
    keywords = [record.data[key] for key in record.keywords if key in record.data]
    matching_entries = search_for_record(keywords, record.is_fuzzy)
    key = key.encode()
    encrypter = SymmetricCryptoAbstraction(key)
    if not matching_entries:
        pseudonym, added_record = add_record(record, key, record.is_fuzzy)
        data = []
        data.append((pickle.loads(encrypter.decrypt(added_record)), pseudonym))
        return data

    decoded_data = [
        (pickle.loads(encrypter.decrypt(word)), p) for word, p in matching_entries
    ]
    return decoded_data


def add_record(
    record: PseudonymRequest, enc_key: bytes, enable_fuzzy_search: bool
) -> bool:
    """Add an encrypted record to the vault

    Args:
        record (PseudonymRequest): a pseudonym request
        enc_key (bytes): an encryption key to encrypt documents
        enable_fuzzy_search (bool): if fuzzy indizes should be created

    Returns:
        bool: true if adding the record was successfull
    """
    document = write(record, enc_key, enable_fuzzy_search)
    response = requests.post(
        f"{API_URL}/addRecord",
        json={"record": document[0], "indices": document[1]},
        timeout=10,
    )

    if response.ok:
        return response.json()
    raise HTTPException(status_code=503, detail=response.json())


def search_for_record(keywords: List[str], fuzzy_search: bool) -> List:
    """Searches for records in the vault and returns them if they match the search words

    Args:
        keywords (List[str]): a list of keywords to search for
        fuzzy_search (bool): if the search should be fuzzy

    Returns:
        List: a list of matching records
    """
    query_key = DB.hget(f"users:{MY_ID}", "queryKey")
    queries_list = []
    if fuzzy_search:
        wildcard_lists = generate_wildcard_list(keywords)
        for wildcard_list in wildcard_lists:
            user_id, queries = construct_query(
                GROUP.deserialize(query_key.encode(), compression=False), wildcard_list
            )
            serialized_queries = [
                GROUP.serialize(query, compression=False).decode() for query in queries
            ]
            queries_list.append(serialized_queries)
    else:
        user_id, queries = construct_query(
            GROUP.deserialize(query_key.encode(), compression=False), keywords
        )
        serialized_queries = [
            GROUP.serialize(query, compression=False).decode() for query in queries
        ]
        queries_list.append(serialized_queries)

    response = requests.post(
        f"{API_URL}/search",
        json={
            "user_id": user_id,
            "queries": queries_list,
            "is_fuzzy": fuzzy_search,
            "expected_amount_of_keywords": len(keywords),
        },
        timeout=20,
    )
    if response.ok:
        return response.json()
    raise HTTPException(status_code=503, detail=response.json())
