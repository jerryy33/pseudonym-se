"""Api for storing, writing and searching searchable encrypted data"""
from typing import List, Union
from fastapi import FastAPI, HTTPException
from constants import PSEUDONYM_ENTRIES, GROUP  # pylint: disable=no-name-in-module
from db import database  # pylint: disable=no-name-in-module
from se import revoke_access, search  # pylint: disable=no-name-in-module
from pseudonyms import generate_pseudonym

app = FastAPI()


@app.get("/generateIndex")
def gen_index(user_id: int, hashed_keyword: bytes) -> bytes:
    com_key = database.get(user_id)
    print(com_key)
    # print(f"Got comp key from database{com_key}")
    # answer = GROUP.serialize(
    #     GROUP.pair_prod(
    #         GROUP.deserialize(hashed_keyword), GROUP.deserialize(com_key.encode())
    #     )
    # )
    # print(f"Sending answer as {answer}, expected received value is {GROUP.deserialize(answer)}")
    if com_key is None:
        raise HTTPException(
            status_code=403, detail="User is not authorized to generate index"
        )
    # print(f"comp key serialized as  {GROUP.deserialize(com_key.encode())}")
    return GROUP.serialize(
        GROUP.pair_prod(
            GROUP.deserialize(hashed_keyword, compression=False),
            GROUP.deserialize(com_key.encode(), compression=False),
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
    # print(f"Received query_key as {query}, deserilized to {GROUP.deserialize(query)}")
    return search((user_id, GROUP.deserialize(query, compression=False)))


@app.post("/revoke")
def revoke(user_id: int) -> bool:
    return revoke_access(user_id)


@app.post("/addUser")
def add_user(user_id: int, comp_key: bytes) -> Union[bool, None]:
    # set user_id as key and complementary key as value
    # print(
    #   f"Received comp key serialized as {comp_key}, is actually {GROUP.deserialize(comp_key)}")
    return database.set(user_id, comp_key)
