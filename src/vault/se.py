"""Searchable encryption algorithms"""
from typing import Any, List
from fastapi import HTTPException
from charm.toolbox.symcrypto import SymmetricCryptoAbstraction
from constants import GROUP
from hashes import h
from db import database  # pylint: disable=no-name-in-module


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
def search(user_id: int, queries: List[Any]) -> List:
    """Searches for records that fit to the given query.
    If a word is equal to a search query is determined through simple equality checks.
    However since this search algorithm is used for searchable encryption the equality is
    based on bilinear pairing properties


    Args:
        user_id (int): user identifier
        queries (List[str]): a list of queries

    Returns:
        List: contains all records that equal the search word.
        None if no record was found
    """
    com_k = database.get(user_id)
    if com_k is None:
        raise HTTPException(status_code=403, detail="User is not authorized to search")
    com_k = GROUP.deserialize(com_k.encode(), compression=False)
    decryption_keys: List[bytes] = []
    for query in queries[0]:
        decryption_keys.append(h(GROUP, GROUP.pair_prod(query, com_k)))

    results = []
    keys = database.scan_iter(_type="HASH")
    key: str
    for key in keys:
        query_hits = 0
        print("set back and key is:", key)
        for index_key in decryption_keys:
            aes = SymmetricCryptoAbstraction(index_key)

            # print(f"Key is:{index_key}")
            indices = database.hscan_iter(key, "index:*")
            print(query_hits, "wow")
            for _, index in indices:
                # print(f"Value is:{_}")
                e_index = index.split(sep=",", maxsplit=1)
                # print("list of indexes", e_index)
                if len(e_index) != 2:
                    print("The key was not a expected index", e_index)
                    print("length was", len(e_index))
                    continue
                inn: bytes = aes.decrypt(e_index[1])
                print("decoded:", inn.decode(errors="replace"))
                if e_index[0] == inn.decode(errors="replace"):
                    print("hit")
                    query_hits += 1
        print(query_hits, len(queries[0]))
        if len(queries[0]) == query_hits and query_hits > 0:
            record = database.hget(key, "record")
            pseudonym = database.hget(key, "pseudonym")
            results.append((record, pseudonym))
    # print(f"results are: {results}")
    return results


def fuzzy_search(
    user_id: int, queries: List[List[Any]], expected_amount_of_keywords: int = 1
) -> List:
    """Performs fuzzy search for the given queries, equality is based on a wildcard approach

    Args:
        user_id (int): user identifier
        queries (List[List[Any]]): a list for each keyword containing a list of queries
        expected_amount_of_keywords (int, optional): The amount of keywords to search for. Defaults to 1.

    Raises:
        HTTPException: if the user is not authorized to search

    Returns:
        List: a list of matching records
    """
    com_k = database.get(user_id)
    if com_k is None:
        raise HTTPException(status_code=403, detail="User is not authorized to search")
    com_k = GROUP.deserialize(com_k.encode(), compression=False)
    search_tokens = []
    for q in queries:
        tmp = []
        for token in q:
            print(token)
            tmp.append(h(GROUP, GROUP.pair_prod(token, com_k)))
        search_tokens.append(tmp)

    results = []
    keys = database.scan_iter(_type="HASH")
    key: str
    # index_containers = len(search_tokens)
    for key in keys:
        query_hits = 0
        # print(f"Key is:{key}")
        # print(index_containers)
        # TODO find a way to make 3 variable
        for index_number in range(0, 3):
            for search_token_keyword_list in search_tokens[:]:
                indices = database.hscan_iter(key, f"index:{index_number}:*")
                index: str
                for _, index in indices:
                    for search_token in search_token_keyword_list:
                        aes = SymmetricCryptoAbstraction(search_token)
                        # print(f"Value is:{index} and key is {_}")
                        e_index = index.split(sep=",", maxsplit=1)
                        # print("list of indexes", e_index)
                        if len(e_index) != 2:
                            print("The key was not a expected index", e_index)
                            print("length was", len(e_index))
                            continue
                        inn: bytes = aes.decrypt(e_index[1])
                        if e_index[0] == inn.decode(errors="replace"):
                            query_hits += 1
                            search_tokens.remove(search_token_keyword_list)
                            break
                    else:
                        continue
                    break
                else:
                    continue
                break
        print(query_hits)
        if query_hits == expected_amount_of_keywords and query_hits > 0:
            record = database.hget(key, "record")
            pseudonym = database.hget(key, "pseudonym")
            results.append((record, pseudonym))
    # print(f"results are: {results}")
    return results
