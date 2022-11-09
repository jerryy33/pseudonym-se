"""Utility functions"""
import secrets
import string
from typing import List, Union


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


def generate_wildcard_list(words: Union[List, str]) -> List[List[str]]:
    """Generates a wildcard list for a single word or list of words,
    produces list of length n*2 +1 where n = len(word)
        Example:
        words = hallo
        --> 1. *hallo
            2. *allo
            3. h*allo
            4. h*llo
            5. ha*llo
            6. ha*lo
            7. hal*lo
            8. hal*o
            9. hall*o
           10. hall*
           11. hallo*

    Args:
        words (Union[List, str]): a list of words or single word

    Returns:
        List[List[str]]: a list of wildcard lists
    """
    if isinstance(words, str):
        words = [words]
        wildcard_list = [words]
    else:
        wildcard_list = []
    for word in words:
        keyword_wildcard_list = [word]
        for i in range(0, len(word) + 1):
            wildcard1 = word[:i] + "*" + word[i:]
            keyword_wildcard_list.append(wildcard1)
            if i == len(word):
                break
            wildcard2 = word[:i] + "*" + word[i + 1 :]
            keyword_wildcard_list.append(wildcard2)
        wildcard_list.append(keyword_wildcard_list)
    return wildcard_list
