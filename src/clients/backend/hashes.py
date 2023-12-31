"""This module provides hash functions that convert
from or to a group Element to hashed value or new group element"""
import hmac
from hashlib import sha256
from typing import Optional, Any
from charm.toolbox.pairinggroup import PairingGroup, G1


def hs(
    group: PairingGroup,
    object_to_hash: Any,
    element_type=G1,
    seed: Optional[str] = None,
) -> Any:
    """Hashes a given string with the hash function of the given group element.

    A seed can be used to make this a keyed hashed function.

    hs: S x W --> G1.
    G1 could also be G2 or ZR.

    Args:
        group (PairingGroup): pairing Group with a defined hash function
        object_to_hash (Any): object to hash
        elementType(optional): type of the group to hash to. Allowed values are [G1, G2, ZR]
        seed (Optional[str], optional): A random seed. Defaults to None.

    Returns:
        pairing.Element: a group element of type elementType
    """

    keyed_hashed_object = hmac.digest(seed, object_to_hash.encode(), sha256)
    return group.hash(keyed_hashed_object, type=element_type)


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
