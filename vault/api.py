"""Api for storing, writing and searching searchable encrypted data"""
from typing import List, Union
from fastapi import FastAPI, HTTPException
from constants import PSEUDONYM_ENTRIES, GROUP  # pylint: disable=no-name-in-module
from db import database  # pylint: disable=no-name-in-module
from se import revoke_access, search, fuzzy_search  # pylint: disable=no-name-in-module
from pseudonyms import generate_pseudonym
from models import AddRequest, SearchRequest  # pylint: disable=no-name-in-module

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
def add_record(request: AddRequest) -> int:
    pseudonym = generate_pseudonym(request.record)
    database.incr("hash_name_index", 1)
    hash_index = database.get("hash_name_index")
    print(hash_index, f"{PSEUDONYM_ENTRIES}:{hash_index}")
    # TODO use pipeline to make this secure for multiple users
    for keyword_number, index_list in enumerate(request.indices):
        for index_number, index in enumerate(index_list):
            combined_index = ",".join(index)
            # print(combined_index, index)
            database.hset(
                f"{PSEUDONYM_ENTRIES}:{hash_index}",
                f"index:{keyword_number}: {index_number}",
                combined_index,
            )

    database.hset(f"{PSEUDONYM_ENTRIES}:{hash_index}", "pseudonym", pseudonym)
    database.hset(f"{PSEUDONYM_ENTRIES}:{hash_index}", "record", request.record)
    return (pseudonym, request.record)


@app.post("/search")
def search_records(request: SearchRequest) -> List:
    # print(f"Received query_key as {query}, deserilized to {GROUP.deserialize(query)}")
    search_queries = [
        [GROUP.deserialize(query.encode(), compression=False) for query in queries]
        for queries in request.queries
    ]
    # print(search_queries)
    if request.is_fuzzy:
        return fuzzy_search(
            request.user_id, search_queries, request.expected_amount_of_keywords
        )
    return search(request.user_id, search_queries[0])


@app.post("/revoke")
def revoke(user_id: int) -> bool:
    return revoke_access(user_id)


@app.post("/addUser")
def add_user(user_id: int, comp_key: bytes) -> Union[bool, None]:
    # set user_id as key and complementary key as value
    # print(
    #   f"Received comp key serialized as {comp_key}, is actually {GROUP.deserialize(comp_key)}")
    return database.set(user_id, comp_key)
