"""This module represents a user-manager that is responsible for rolling out and revoking users
that want to request pseudonyms"""
from typing import Any
import urllib.parse
from charm.toolbox.pairinggroup import ZR, G1, G2, extract_key
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import requests
import redis
from constants import USER_MANAGER_DB, API_URL, CLIENT_URL_LIST, GROUP, UA, UR
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
def start_setup() -> str:
    """Starts the setup process and produces paramters to used to enroll future users

    Returns:
        str: a string indicating if the process was successful
    """
    management_key, group_element_for_key, enc_key, seed = setup()
    redis.mset(
        mapping={
            "management_key": management_key,
            "group_element_for_key": GROUP.serialize(
                group_element_for_key, compression=False
            ),
            "enc_key": f"{enc_key}",
            "seed": GROUP.serialize(seed, compression=False),
        }
    )
    return "OK"


@app.post("/enroll/{user_id}")
def enroll_user(user_id: int) -> bool:
    """Enrolls a user for the given user id

    Args:
        user_id (int): integer representing the id of a user

    Raises:
        HTTPException: when the user is not known or the enroll process failed

    Returns:
        bool: if the enrollment was successful
    """
    group_element_for_key = GROUP.deserialize(
        redis.get("group_element_for_key").encode(), compression=False
    )
    enc_key = redis.get("enc_key")
    seed = GROUP.deserialize(redis.get("seed").encode(), compression=False)
    user_detail = enroll(user_id, group_element_for_key)
    client_url = next(
        (client["url"] for client in CLIENT_URL_LIST if int(client["id"]) == user_id),
        None,
    )
    if client_url is None:
        raise HTTPException(
            status_code=400, detail="User is not known to the user-manager"
        )
    response = requests.put(
        f"{client_url}/receiveSecurityDetails",
        json={
            "query_key": GROUP.serialize(user_detail, compression=False).decode(),
            "seed": GROUP.serialize(seed, compression=False).decode(),
            # TODO for some reason this key cannot be decoded normally, maybe send the GROUP element
            # and call "extract_key" on the clients
            "encryption_key": f"{enc_key}",
            "user_id": user_id,
        },
        timeout=10,
    )
    if response.ok:
        res = response.json()
        return res in (3, 0)
    raise HTTPException(status_code=response.status_code, detail=response.json())


@app.post("/revoke")
def revoke_user(user_id: int) -> bool:
    """Revokes search rights for a user

    Args:
        user_id (int): id for a user

    Returns:
        bool: if the revocation was successful
    """
    return revoke(user_id)


def setup() -> SetupParams:
    """Executes the setup process for the complete system.
    Will generate a bunch of system parameters necessary for searchable encryption.

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
    s = GROUP.random(G1)
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
        group_element (Any): the group element from the private key of this instance

    Raises:
        HttpException: if a user already exists or adding a new one failed

    Returns:
        Any:  a random element from ZR
    """
    xu = GROUP.random(ZR)
    g = GROUP.random(G1)
    com_k = g ** (group_element / xu)
    send_key: bytes = GROUP.serialize(com_k, compression=False)
    successfull = requests.post(
        f"{API_URL}/addUser",
        params={"user_id": user_id, "comp_key": send_key},
        timeout=10,
    ).json()
    if successfull:
        rows = redis.sadd(UA, user_id)
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
