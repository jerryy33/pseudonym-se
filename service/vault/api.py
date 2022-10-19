"""Api for storing, writing and searching searchable encrypted data"""
import os
from typing import List, Tuple, Union, Any
from fastapi import FastAPI, HTTPException
from charm.toolbox.pairinggroup import PairingGroup
from charm.toolbox.symcrypto import SymmetricCryptoAbstraction
import urllib.parse
import redis
import requests
from dotenv import load_dotenv
from ...hashes import h

load_dotenv()
Index = Tuple[str, str]

app = FastAPI()
API_DB = os.environ.get("API_DB")
db = urllib.parse.urlsplit(API_DB)
database = redis.Redis(host=db.hostname, port=db.port, db=0, decode_responses=True)

# Local constants

UM_URL = os.environ.get("USER_MANAGER_URL")
PSEUDONYM_ENTRIES = os.environ.get("PSEUDONYM_ENTRIES")
group_id = requests.get(f"{UM_URL}/publicParams", timeout=10).json()
group = PairingGroup(group_id)


@app.get("/generateIndex")
def gen_index(user_id: int, hashed_keyword: bytes) -> bytes:
    com_key = database.get(user_id)
    print(com_key)
    # print(f"Got comp key from database{com_key}")
    # answer = group.serialize(
    #     group.pair_prod(
    #         group.deserialize(hashed_keyword), group.deserialize(com_key.encode())
    #     )
    # )
    # print(f"Sending answer as {answer}, expected received value is {group.deserialize(answer)}")
    if com_key is None:
        raise HTTPException(
            status_code=403, detail="User is not authorized to generate index"
        )
    # print(f"comp key serialized as  {group.deserialize(com_key.encode())}")
    return group.serialize(
        group.pair_prod(
            group.deserialize(hashed_keyword, compression=False),
            group.deserialize(com_key.encode(), compression=False),
        ),
        compression=False,
    )


@app.post("/addRecord")
def add_record(record: str, index1: str, index2: str) -> int:
    pseudonym = generate_pseudonym(record)
    index = index1 + "," + index2

    database.incr("hash_name_index", 1)
    hash_index = database.get("hash_name_index")
    print(hash_index, f"{PSEUDONYM_ENTRIES}:{hash_index}")
    # TODO use pipeline to make this secure for multiple users
    index_fields = database.hset(f"{PSEUDONYM_ENTRIES}:{hash_index}", "index", index)
    pseudonym_fields = database.hset(
        f"{PSEUDONYM_ENTRIES}:{hash_index}", "pseudonym", pseudonym
    )
    record_fields = database.hset(f"{PSEUDONYM_ENTRIES}:{hash_index}", "record", record)
    return (pseudonym, record, index_fields + pseudonym_fields + record_fields)


@app.get("/search")
def search_records(user_id: int, query: bytes) -> List:
    # print(f"Received query_key as {query}, deserilized to {group.deserialize(query)}")
    return search((user_id, group.deserialize(query, compression=False)))


@app.post("/revoke")
def revoke(user_id: int) -> bool:
    return revoke_access(user_id)


@app.post("/addUser")
def add_user(user_id: int, comp_key: bytes) -> Union[bool, None]:
    # set user_id as key and complementary key as value
    # print(
    #   f"Received comp key serialized as {comp_key}, is actually {group.deserialize(comp_key)}")
    return database.set(user_id, comp_key)


def revoke_access(user_id: int) -> bool:
    """Revokes access, by deleting the entry for a given user id in the access list

    Args:
        user_id (int): identifier for a user

    Returns:
        bool: true if the user had a single entry that was removed
    """
    u_comp_key = database.get(user_id)
    print(f"Revoking user with key {u_comp_key}")
    if u_comp_key is not None:
        deleted_rows = database.delete(user_id)
        print(f"Revoked {deleted_rows} rows")
        return deleted_rows == 1
    raise HTTPException(
        status_code=400, detail="User has already been revoked or couldn't be found"
    )


# TODO check performance
def search(query: Tuple[int, Any]) -> List:
    """Searches for records that fit to the given query.
    If a word is equal to search query is determined through simple equality checks.
    However since this search algorithm is used for searchable encryption the equality is
    based on bilinear pairing properties

    Args:
        query (Tuple[int, Any]): a query containing the user id and a group element computed
        at the client side

    Returns:
        List: contains all records that equal the search word.
        None if no record was found or the user had no rights to search
    """
    com_k = database.get(query[0])
    # print(f"Got com key from database as {com_k}")
    if com_k is None:
        raise HTTPException(status_code=403, detail="User is not authorized to search")
    com_k = group.deserialize(com_k.encode(), compression=False)
    # print(f"Serialized back to {com_k}")
    # print(f"using query key as {query[1]}")
    k_1 = h(group, group.pair_prod(query[1], com_k))
    aes = SymmetricCryptoAbstraction(k_1)
    results = []
    keys = database.scan_iter(_type="HASH")
    for key in keys:
        print(f"Key is:{key}")
        index = database.hget(key, "index")
        print(f"Value is:{index}")
        e_index = index.split(sep=",", maxsplit=1)
        # print("list of indexes", e_index)
        if len(e_index) != 2:
            print("The key was not a expected index", e_index)
            print("length was", len(e_index))
            continue
        inn: bytes = aes.decrypt(e_index[1])
        # print("decoded:", inn)
        if len(inn) < 0:
            print(inn, e_index[0], e_index[1])
        if e_index[0] == inn.decode(errors="replace"):
            record = database.hget(key, "record")
            pseudonym = database.hget(key, "pseudonym")
            results.append((record, pseudonym))
    return results


def generate_pseudonym(record: str) -> str:
    # TODO
    return "pseudonym"
