"""Module that produces truly random pseudonyms"""
import secrets
import string


def generate_pseudonym(record: str) -> str:
    # TODO generate valid truly random pseudonym
    return generate_random_string(16)


def generate_random_string(length: int) -> str:
    """Generate a random string for a given length.
    Contains digits and uppercase letters only

    Args:
        length (int): length of the generated random string

    Returns:
        str: random string
    """
    return "".join(
        secrets.choice(string.ascii_uppercase + string.digits) for _ in range(length)
    )
