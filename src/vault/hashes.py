"""This module provides hash functions that convert
from or to a group Element to hashed value or new group element"""
from hashlib import sha256
from typing import Any
from charm.toolbox.pairinggroup import PairingGroup


def h(group: PairingGroup, group_element: Any) -> bytes:
    """Hash function which maps a group element to a hash value,
    which can be used as a secret key.

    h: G2 --> K

    Args:
        group (PairingGroup): serializes the group element
        groupElement (pairing.Element): element in G2 to map to hash value

    Returns:
        bytes: a hashed group element
    """
    return sha256(group.serialize(group_element, compression=False)).digest()
