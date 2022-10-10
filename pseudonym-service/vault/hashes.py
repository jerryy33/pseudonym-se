from hashlib import sha256
from typing import Optional, Any
from charm.toolbox.pairinggroup import PairingGroup, G1


def hs(
    group: PairingGroup, w: bytes, element_type=G1, seed: Optional[str] = None
) -> Any:
    """Hashes a given string with the hash function of the given group element.

    A seed can be used to make this a keyed hashed function.

    hs: S x W --> G1.
    G1 could also be G2 or ZR.

    Args:
        group (PairingGroup): pairing Group with a defined hash function
        w (bytes): encoded keyword
        elementType(optional): type of the group to hash to. Allowed values are [G1, G2, ZR]
        seed (Optional[str], optional): A random seed. Defaults to None.

    Returns:
        pairing.Element: a group element of type elementType
    """

    # TODO find out how to integrate s
    return group.hash(w, type=element_type)


def h(group: PairingGroup, group_element) -> bytes:
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
