import os, sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from template_system import setup, enroll, construct_query, write, search_opt, search
from line_profiler import LineProfiler

test_dict = {
    "keywords": ["name", "surname", "socialSecurityNumber"],
    "data": {
        "name": "Jeremy",
        "surname": "Herbst",
        "socialSecurityNumber": "1536363",
    },
}


def init():
    UM_RANDOM, ENCRYPTER, SEED = setup()
    complementary_key, query_key = enroll(1, UM_RANDOM, SEED)

    _, queries = construct_query(query_key, ["Herbst", "Jeremy", "1536363"])

    for _ in range(0, 100):
        write(ENCRYPTER, query_key, complementary_key, test_dict, False)
    return complementary_key, queries


complementary_key, query = init()
lp = LineProfiler()
lp_wrapper = lp(search_opt)
lp_wrapper(queries=query, complementary_key=complementary_key)
lp.print_stats()
# Run kernprof -l -o lines.txt line_performance.py or
# lp.dump_stats("lines.txt")
