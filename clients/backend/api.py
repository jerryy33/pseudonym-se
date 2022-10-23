"""This module represent a data client that can request pseudonyms from a server"""
from typing import List
import pickle
import requests
from charm.toolbox.symcrypto import SymmetricCryptoAbstraction
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

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
    print(added_fields)
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
    print(record)
    key = DB.hget(f"users:{MY_ID}", "encryptionKey").encode()
    keywords = [record.data[key] for key in record.keywords if key in record.data]
    print(keywords)
    matching_entries = search_for_record(keywords)
    print(matching_entries)
    encrypter = SymmetricCryptoAbstraction(key)
    if not matching_entries:
        pseudonym, added_record, added_rows = add_record(record, key)
        print(added_rows)
        if added_rows != 3:
            print(
                f"Adding a new record failed on the server only {added_rows}"
                "rows were added but should be 3"
            )
            raise HTTPException(status_code=503, detail="Pseudonym request failed")
        data = []
        data.append((pickle.loads(encrypter.decrypt(added_record)), pseudonym))
        return data

    decoded_data = [
        (pickle.loads(encrypter.decrypt(word)), p) for word, p in matching_entries
    ]
    return decoded_data


def add_record(record: PseudonymRequest, enc_key: bytes) -> bool:
    """Add an encrypted record to the vault

    Args:
        record (str): a encrypted record

    Returns:
        bool: true if adding the record was successfull
    """
    document = write(record, enc_key)
    index = document[1]
    # print(document)
    return requests.post(
        f"{API_URL}/addRecord",
        params={"record": document[0], "index1": index[0], "index2": index[1]},
        timeout=10,
    ).json()


def search_for_record(keywords: List[str]) -> List:
    """Searches for records in the vault and returns them if they match the search record

    Args:
        record (str): a record to search for

    Returns:
        List: a list of matching records
    """
    query_key = DB.hget(f"users:{MY_ID}", "queryKey")
    query = construct_query(GROUP.deserialize(query_key.encode()), keywords)
    return requests.get(
        f"{API_URL}/search",
        params={
            "user_id": query[0],
            "query": GROUP.serialize(query[1], compression=False),
        },
        timeout=10,
    ).json()
