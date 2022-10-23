"""Searchable encryption algorithms"""
from typing import Tuple, Any, List
from fastapi import HTTPException
from charm.toolbox.symcrypto import SymmetricCryptoAbstraction
from constants import GROUP
from hashes import h
from db import database


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
        query (Tuple[int, Any]): a query containing the user id and a GROUP element computed
        at the client side

    Returns:
        List: contains all records that equal the search word.
        None if no record was found or the user had no rights to search
    """
    com_k = database.get(query[0])
    # print(f"Got com key from database as {com_k}")
    if com_k is None:
        raise HTTPException(status_code=403, detail="User is not authorized to search")
    com_k = GROUP.deserialize(com_k.encode(), compression=False)
    # print(f"Serialized back to {com_k}")
    # print(f"using query key as {query[1]}")
    k_1 = h(GROUP, GROUP.pair_prod(query[1], com_k))
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
