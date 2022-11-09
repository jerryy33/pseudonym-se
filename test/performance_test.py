from test.test import setup, enroll, construct_query, gen_indizes, search
import time


def test_performance_gen_indizes():
    UM_RANDOM, ENCRYPTER, SEED = setup()
    complementary_key, query_key = enroll(1, UM_RANDOM, SEED)
    start = time.time()
    for _ in range(0, 1000):
        gen_indizes(query_key, ["hallo", "bye", "cia"], complementary_key)
    end = time.time()
    print(end - start)
