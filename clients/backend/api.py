"""This module represent a data client that can request pseudonyms from a server"""
from typing import List
import pickle
import requests
from charm.toolbox.symcrypto import SymmetricCryptoAbstraction
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
def receive_security_details(details: SecurityDetails):
    if details.user_id != MY_ID:
        raise HTTPException(
            status_code=400,
            detail="Security Details were not meant to be for this user",
        )
    added_fields = DB.hset(
        f"users:{MY_ID}",
        mapping={
            "queryKey": details.query_key,
            "seed": details.seed,
            "encryptionKey": details.encryption_key,
        },
    )
    # print(added_fields)
    return added_fields


@app.post("/requestPseudonym")
def request_pseudonym(record: PseudonymRequest) -> List:
    """Requests a pseudonym for a given data record, if no entry on the server is found
    adds a new encrypted record to the server. If multiple record match, the user can choose the one
    thats actually correct

    Args:
        record (Dict): a given data record as dictionary

    Returns:
        List: a list containing pseudonyms and the matching record
    """
    # print(record)
    key = DB.hget(f"users:{MY_ID}", "encryptionKey").encode()
    keywords = [record.data[key] for key in record.keywords if key in record.data]
    # print(keywords)
    matching_entries = search_for_record(keywords, record.is_fuzzy)
    print(matching_entries)
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
        record (str): a encrypted record

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
    """Searches for records in the vault and returns them if they match the search record

    Args:
        record (str): a record to search for

    Returns:
        List: a list of matching records
    """
    query_key = DB.hget(f"users:{MY_ID}", "queryKey")
    if fuzzy_search:
        wildcard_list = generate_wildcard_list(keywords)
        wildcard_list = [item for sublist in wildcard_list for item in sublist]

    user_id, queries = construct_query(
        GROUP.deserialize(query_key.encode()),
        wildcard_list if fuzzy_search else keywords,
    )
    serialized_queries = [
        GROUP.serialize(query, compression=False).decode() for query in queries
    ]

    response = requests.post(
        f"{API_URL}/search",
        json={
            "user_id": user_id,
            "queries": serialized_queries,
            "is_fuzzy": fuzzy_search,
            "expected_amount_of_keywords": len(keywords),
        },
        timeout=20,
    )
    if response.ok:
        return response.json()
    raise HTTPException(status_code=503, detail=response.json())
