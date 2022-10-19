"""This module represents a user-manager that is responsible for rolling out and revoking users
that want to request pseudonyms"""
from typing import Any
import urllib.parse
from charm.toolbox.pairinggroup import ZR, G1, G2, GT, extract_key
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import requests
import redis
from constants import USER_MANAGER_DB, API_URL, CLIENT_URL, GROUP, UA, UR
from aliases import SetupParams

app = FastAPI()
origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


db = urllib.parse.urlsplit(USER_MANAGER_DB)
redis = redis.Redis(host=db.hostname, port=db.port, db=0, decode_responses=True)


@app.post("/setup")
def start_setup():
    management_key, group_element_for_key, enc_key, seed = setup()
    redis.mset(
        mapping={
            "management_key": management_key,
            "group_element_for_key": group_element_for_key,
            "enc_key": enc_key,
            "seed": seed,
        }
    )
    return "OK"


@app.post("/enroll/{user_id}")
def enroll_user(user_id: int) -> bool:
    group_element_for_key = redis.get("group_element_for_key")
    enc_key = redis.get("enc_key")
    seed = redis.get("seed")
    user_detail = enroll(user_id, group_element_for_key)
    print(user_detail[0])

    response = requests.put(
        f"{CLIENT_URL}/receiveSecurityDetails",
        json={
            "query_key": GROUP.serialize(user_detail[0], compression=False).decode(),
            "seed": seed,
            # TODO for some reason this key cannot be decoded normally, maybe send the GROUP element
            # and call "extract_key" on the clients
            "encryption_key": f"{enc_key}",
            "user_id": user_id,
        },
        timeout=10,
    )
    if response.ok:
        res = response.json()
        print(res)
        return res in (3, 0)
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
        - x: the according GROUP element to key
        - e: symmetric encryption key for documents
        - s: random seed to use for hashing on the clients


    """

    # Generate encryption key e
    r = GROUP.random(G2)
    e = extract_key(r)

    # extract x
    x = GROUP.random(ZR)
    # generate kum
    key = extract_key(x)
    # print(random, key)
    s = GROUP.random(GT)
    return (
        key,
        x,
        e,
        s,
    )


def enroll(user_id: int, group_element: Any) -> Any:
    """Enrolls a user with a given user identifier to the system.

    Will try to send a generated complementary key to the vault

    Args:
        user_id (int): A given user identifier
        group_element (tuple): the GROUP element from the private key of this instance

    Raises:
        RuntimeError: If a adding a user to the vault failed

    Returns:
        Tuple[bytes, bytes]:  a tuple containing a random element from ZR
        and the seed generated in setup()
    """
    xu = GROUP.random(ZR)
    g = GROUP.random(G1)
    com_k = g ** (group_element / xu)
    # print(com_k)
    send_key: bytes = GROUP.serialize(com_k, compression=False)
    print(f"Sending comp key{com_k} to serv serialized as {send_key}")
    successfull = requests.post(
        f"{API_URL}/addUser",
        params={"user_id": user_id, "comp_key": send_key},
        timeout=10,
    ).json()
    print(f"Adding user ended with status {successfull}")
    if successfull:
        rows = redis.sadd(UA, user_id)
        print(rows)
        if rows == 0:
            raise HTTPException(status_code=400, detail="User already exists")
    else:
        raise HTTPException(status_code=500, detail="Adding user failed")
    return xu


def revoke(user_id: int) -> bool:
    """Revokes a user with a given id from the system.
    Sends a request to the vault to delete the user entry there. If this fails for some
    reason a user will still have access rights even if he is marked here as a revoked user

    Args:
        user_id (int): user identifier

    Returns:
        bool: true if the user was successfully revoked false otherwise

    """
    redis.srem(UA, user_id)
    redis.sadd(UR, user_id)

    response = requests.post(
        f"{API_URL}/revoke", params={"user_id": user_id}, timeout=10
    )
    if response.ok:
        return response.json()
    raise HTTPException(status_code=response.status_code, detail=response.json())
