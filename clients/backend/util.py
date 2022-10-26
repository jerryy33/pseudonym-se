import secrets
import string
from typing import List, Union


def generate_random_string(length: int) -> str:
    """Generate a random string for a given length.
    Contains digits and uppercase letters only


    Args:
        len (int): length of the generated random string

    Returns:
        str: random string
    """
    return "".join(
        secrets.choice(string.ascii_uppercase + string.digits) for _ in range(length)
    )


def generate_wildcard_list(words: Union[List, str]) -> List[List[str]]:
    # produces list of length n*2 +1 where n = len(word)
    if isinstance(words, str):
        words = [words]
        wildcard_list = [words]
    else:
        wildcard_list = []
    # print(words, wildcard_list)
    for word in words:
        # print(word)
        keyword_wildcard_list = [word]
        for i in range(0, len(word) + 1):
            wildcard1 = word[:i] + "*" + word[i:]
            # print("Wildcard1 is: ", wildcard1)
            keyword_wildcard_list.append(wildcard1)
            if i == len(word):
                break
            wildcard2 = word[:i] + "*" + word[i + 1 :]
            # print("Wildcard2 is: ", wildcard2)

            keyword_wildcard_list.append(wildcard2)
        wildcard_list.append(keyword_wildcard_list)
    return wildcard_list
