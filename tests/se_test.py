import pickle
from tests.template_system import (
    gen_index,
    setup,
    enroll,
    search,
    construct_query,
    revoke,
    write,
)

test_dict = {
    "keywords": ["name", "surname", "socialSecurityNumber"],
    "data": {
        "name": "Jeremy",
        "surname": "Herbst",
        "socialSecurityNumber": "1536363",
    },
}


def test_gen_index():
    UM_RANDOM, _, SEED = setup()
    complementary_key, query_key = enroll(1, UM_RANDOM, SEED)
    random_string, encrypted_index = gen_index(query_key, complementary_key, "hallo")
    revoke(1)
    assert len(random_string) == 16
    assert encrypted_index is not None


def test_constructQuery():
    UM_RANDOM, _, SEED = setup()
    _, query_key = enroll(1, UM_RANDOM, SEED)

    user_id, queries = construct_query(query_key, ["word1", "word2"])
    revoke(1)
    assert user_id == 1
    assert queries is not None
    assert len(queries) == 2


def test_write():
    UM_RANDOM, ENCRYPTER, SEED = setup()
    comp_key, query_key = enroll(1, UM_RANDOM, SEED)
    success = write(ENCRYPTER, query_key, comp_key, test_dict, False)
    revoke(1)
    assert success


def test_search():
    UM_RANDOM, ENCRYPTER, SEED = setup()
    comp_key, query_key = enroll(1, UM_RANDOM, SEED)
    write(ENCRYPTER, query_key, comp_key, test_dict, False)
    _, query = construct_query(query_key, ["Herbst", "Jeremy", "1536363"])

    search_results = search(query, comp_key)
    results = [pickle.loads(ENCRYPTER.decrypt(res)) for res in search_results]
    revoke(1)
    assert len(results) == 1
    assert results[0]["name"] == "Jeremy"
    assert results[0]["socialSecurityNumber"] == "1536363"
