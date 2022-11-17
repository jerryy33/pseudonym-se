"""Api for storing, writing and searching searchable encrypted data"""
from typing import Dict, List, Tuple, Union
from fastapi import FastAPI, HTTPException
from constants import PSEUDONYM_ENTRIES, GROUP  # pylint: disable=no-name-in-module
from db import database  # pylint: disable=no-name-in-module
from se import revoke_access, search, fuzzy_search  # pylint: disable=no-name-in-module
from pseudonyms import generate_pseudonym
from models import (
    AddRequest,
    SearchRequest,
    IndexRequest,
)

app = FastAPI()


@app.post("/generateIndex")
def gen_index(index_request: IndexRequest) -> List[bytes]:
    """Computes a part for generating indizes on an incoming IndexRequest

    Args:
        index_request (IndexRequest): a request for generation indices

    Raises:
        HTTPException: if no complementary key is found

    Returns:
        List[bytes]: a list of hashed keywords
    """
    com_key = database.get(index_request.user_id)
    if com_key is None:
        raise HTTPException(
            status_code=403, detail="User is not authorized to generate index"
        )

    hashed_keywords = [
        GROUP.serialize(
            GROUP.pair_prod(
                GROUP.deserialize(keyword, compression=False),
                GROUP.deserialize(com_key.encode(), compression=False),
            ),
            compression=False,
        )
        for keyword in index_request.hashed_keywords
    ]
    return hashed_keywords


@app.post("/addRecord")
def add_record(request: AddRequest) -> Tuple[str, Dict]:
    """Adds a new record to the database

    Args:
        request (AddRequest): a request for adding a new document

    Returns:
        Tuple[str, Dict]: a tuple containing the generated pseudonym and the corresponding record
    """
    pseudonym = generate_pseudonym(request.record)
    database.incr("hash_name_index", 1)
    hash_index = database.get("hash_name_index")
    print(hash_index, f"{PSEUDONYM_ENTRIES}:{hash_index}")
    # TODO use pipeline to make this secure for multiple users
    for keyword_number, index_list in enumerate(request.indices):
        for index_number, index in enumerate(index_list):
            combined_index = ",".join(index)
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
    """Searches for records that match the given search words

    Args:
        request (SearchRequest): a request to search for data

    Returns:
        List: a list of matching records
    """
    search_queries = [
        [GROUP.deserialize(query.encode(), compression=False) for query in queries]
        for queries in request.queries
    ]
    if request.is_fuzzy:
        return fuzzy_search(
            request.user_id, search_queries, request.expected_amount_of_keywords
        )
    return search(request.user_id, search_queries)


@app.post("/revoke")
def revoke(user_id: int) -> bool:
    """Revokes search rights for a user id

    Args:
        user_id (int): a user identifier

    Returns:
        bool: if the revocation was successful
    """
    return revoke_access(user_id)


@app.post("/addUser")
def add_user(user_id: int, comp_key: bytes) -> Union[bool, None]:
    """Adds a new user to the database

    Args:
        user_id (int): a user identifier
        comp_key (bytes): a complementary key

    Returns:
        Union[bool, None]: if adding the user was successful
    """
    return database.set(user_id, comp_key)
