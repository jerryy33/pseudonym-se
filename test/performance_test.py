from test.test import (
    setup,
    enroll,
    construct_query,
    gen_indizes,
    search,
    write,
    search_opt,
)
import time

test_dict = {
    "keywords": ["name", "surname", "socialSecurityNumber"],
    "data": {
        "name": "Jeremy",
        "surname": "Herbst",
        "socialSecurityNumber": "1536363",
    },
}


def test_performance_gen_indizes():
    UM_RANDOM, ENCRYPTER, SEED = setup()
    complementary_key, query_key = enroll(1, UM_RANDOM, SEED)
    start = time.time()
    for _ in range(0, 1000):
        gen_indizes(query_key, ["hallo", "bye", "cia"], complementary_key)
    end = time.time()
    print(end - start)


def test_performance_search():
    UM_RANDOM, ENCRYPTER, SEED = setup()
    complementary_key, query_key = enroll(1, UM_RANDOM, SEED)

    query = construct_query(query_key, ["Herbst", "Jeremy", "1536363"])

    for _ in range(0, 10000):
        write(ENCRYPTER, query_key, complementary_key, test_dict, False)
    start = time.time()
    search(queries=query, complementary_key=complementary_key)
    end = time.time()
    print(end - start)


def test_performance_search_opt():
    UM_RANDOM, ENCRYPTER, SEED = setup()
    complementary_key, query_key = enroll(1, UM_RANDOM, SEED)

    query = construct_query(query_key, ["Herbst", "Jeremy", "1536363"])

    for _ in range(0, 1000):
        write(ENCRYPTER, query_key, complementary_key, test_dict, False)
    start = time.time()
    search_opt(queries=query, complementary_key=complementary_key)
    end = time.time()
    print(end - start)
