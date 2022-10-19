"""This module represent a data client that can request pseudonyms from a server"""
import os
from typing import Tuple, Any, List
import pickle
import string
import secrets
import urllib.parse
from dotenv import load_dotenv
import requests
import redis

from charm.toolbox.pairinggroup import PairingGroup, ZR
from charm.toolbox.symcrypto import SymmetricCryptoAbstraction
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from .models import PseudonymRequest, SecurityDetails
from ...hashes import hs, h

load_dotenv()
app = FastAPI()
origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
CLIENT_DB = os.environ.get("CLIENT_DB")
db = urllib.parse.urlsplit(CLIENT_DB)
r = redis.Redis(host=db.hostname, port=db.port, db=0, decode_responses=True)
MY_ID = int(os.environ.get("CLIENT_ID"))
API_URL = os.environ.get("API_URL")
UM_URL = os.environ.get("USER_MANAGER_URL")
group = PairingGroup("SS512")

Index = Tuple[str, str]
Document = Tuple[str, Index]


@app.put("/receiveSecurityDetails")
def receive_security_details(details: SecurityDetails):
    if details.user_id != MY_ID:
        raise HTTPException(
            status_code=400,
            detail="Security Details were not meant to be for this user",
        )
    added_fields = r.hset(
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
    key = r.hget(f"users:{MY_ID}", "encryptionKey").encode()
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
    query_key = r.hget(f"users:{MY_ID}", "queryKey")
    query = construct_query(group.deserialize(query_key.encode()), keywords)
    return requests.get(
        f"{API_URL}/search",
        params={
            "user_id": query[0],
            "query": group.serialize(query[1], compression=False),
        },
        timeout=10,
    ).json()


def gen_index(q_key: Any, keywords: List[str]) -> Index:
    """Generates a index used for searchable encryption.
    Will send a request to the vault to compute a part for the encryption key

    Args:
        q_key (Any): a query key necassry to encrypt the index
        keyword (str): a string for which the index will be generated

    Returns:
        Index: a index for the keyword
    """
    random_blind = group.random(ZR)
    index_request = hs(group, keywords) ** random_blind
    print(
        f"Sending index request {index_request} serialized as"
        f"{group.serialize(index_request, compression= False)}"
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
        f"Received answer as {index_answer}, desiralized to"
        f"{group.deserialize(index_answer.encode(), compression= False)}"
    )
    # index_answer = group.pair_prod(index_request[1], comp_key)
    # print(group1.ismember((qk[0]/random_blind)))
    k = h(
        group,
        group.deserialize(index_answer.encode(), compression=False)
        ** (q_key / random_blind),
    )
    print("Gen index key for enc", k)
    index_encrypter = SymmetricCryptoAbstraction(k)
    res = "".join(
        secrets.choice(string.ascii_uppercase + string.digits) for _ in range(16)
    )
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
    query_key = r.hget(f"users:{MY_ID}", "queryKey")
    i_w = gen_index(group.deserialize(query_key.encode()), keywords)
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
        Tuple[int, Any]: a valid query containing the user id and a group element
    """
    query = hs(group, keywords) ** q_key
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


# if __name__ == "__main__":
#     test_dict = {
#         "keywords": ["name", "surname", "socialSecurityNumber"],
#         "data": {
#             "name": "word123456789qwertz",
#             "surname": "Herbst",
#             "socialSecurityNumber": "1536363",
#         },
#     }
#     pseudo, r = request_pseudonym(test_dict)
#     print(pseudo, r)
#     revoke: bool = requests.post(
#         f"{UM_URL}/revoke", params={"user_id": MY_ID}, timeout=10
#     ).json()
#     print(revoke)
#     # should return 403
#     d = search_for_record(["word123456789qwertz", "Herbst", "1536363"])
#     print(d)
