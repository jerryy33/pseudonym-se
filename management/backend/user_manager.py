"""This module represents a user-manager that is responsible for rolling out and revoking users
that want to request pseudonyms"""
import os
import re
from typing import Dict, List, Any, Tuple
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, extract_key  # type: ignore
from fastapi import FastAPI, HTTPException
from dotenv import load_dotenv
import requests
import redis
import urllib.parse
from fastapi.middleware.cors import CORSMiddleware

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

CLIENT_URL = os.environ.get("CLIENT_BACKEND_URL")
API_URL = os.environ.get("API_URL")
USER_MANAGER_DB = os.environ.get("USER_MANAGER_DB")
db = urllib.parse.urlsplit(USER_MANAGER_DB)
r = redis.Redis(host=db.hostname, port=db.port, db=0, decode_responses=True)

SetupParams = Tuple[bytes, Any, PairingGroup, bytes, Any]
group = PairingGroup("SS512")
managament_key: bytes
group_element_for_key: Any
group: PairingGroup
enc_key: bytes
seed: Any
UA = "Authorized-Users-IDs"
UR = "Revoked-User-IDs"


@app.get("/publicParams")
def provide_public_params() -> str:
    return "SS512"


@app.post("/enroll/{user_id}")
def enroll_user(user_id: int) -> bool:
    user_detail = enroll(user_id, group_element_for_key)
    print(user_detail[0])

    response = requests.put(
        f"{CLIENT_URL}/receiveSecurityDetails",
        json={
            "query_key": group.serialize(user_detail[0], compression=False).decode(),
            "seed": group.serialize(user_detail[1], compression=False).decode(),
            # TODO for some reason this key cannot be decoded normally, maybe send the group element
            # and call "extract_key" on the clients
            "encryption_key": f"{enc_key}",
            "user_id": user_id,
        },
        timeout=10,
    )
    if response.ok:
        res = response.json()
        print(res)
        return res == 3 or res == 0
    raise HTTPException(status_code=response.status_code, detail=response.json())


@app.post("/revoke")
def revoke_user(user_id: int) -> bool:
    return revoke(user_id)


def setup() -> SetupParams:
    """Executes the setup process for the complete system.
    Will generate a bunch of system parameter necessary for searchable encryption.

    Returns:
        SetupParams: System parameters ->
        - key: private key for this instance
        - x: the according group element to key
        - group: the pairing group used for bilinear pairings
        - e: symmetric encryption key for documents
        - s: random seed to use for hashing on the clients


    """

    # Generate encryption key e
    r = group.random(G2)
    e = extract_key(r)

    # extract x
    x = group.random(ZR)
    # generate kum
    key = extract_key(x)
    # print(random, key)
    s = group.random(GT)
    return (
        key,
        x,
        group,
        e,
        s,
    )


def enroll(user_id: int, group_element: Any) -> Tuple[bytes, bytes]:
    """Enrolls a user with a given user identifier to the system.

    Will try to send a generated complementary key to the vault

    Args:
        user_id (int): A given user identifier
        group_element (tuple): the group element from the private key of this instance

    Raises:
        RuntimeError: If a adding a user to the vault failed

    Returns:
        Tuple[bytes, bytes]:  a tuple containing a random element from ZR
        and the seed generated in setup()
    """
    xu = group.random(ZR)
    g = group.random(G1)
    com_k = g ** (group_element / xu)
    # print(com_k)
    send_key: bytes = group.serialize(com_k, compression=False)
    print(f"Sending comp key{com_k} to serv serialized as {send_key}")
    successfull = requests.post(
        f"{API_URL}/addUser",
        params={"user_id": user_id, "comp_key": send_key},
        timeout=10,
    ).json()
    print(f"Adding user ended with status {successfull}")
    # TODO add database
    if successfull:
        rows = r.sadd(UA, user_id)
        print(rows)
        if rows == 0:
            raise HTTPException(status_code=400, detail="User already exists")
    else:
        raise HTTPException(status_code=500, detail="Adding user failed")
    return xu, seed


def revoke(user_id: int) -> bool:
    """Revokes a user with a given id from the system.
    Sends a request to the vault to delete the user entry there. If this fails for some
    reason a user will still have access rights even if he is marked here as a revoked user

    Args:
        user_id (int): user identifier

    Returns:
        bool: true if the user was successfully revoked false otherwise

    """
    r.srem(UA, user_id)
    r.sadd(UR, user_id)

    response = requests.post(
        f"{API_URL}/revoke", params={"user_id": user_id}, timeout=10
    )
    if response.ok:
        return response.json()
    raise HTTPException(status_code=response.status_code, detail=response.json())


managament_key, group_element_for_key, group, enc_key, seed = setup()
