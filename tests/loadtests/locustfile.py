import random
import string
from locust import HttpUser, task, tag


def generate_random_string():
    return "".join(random.choices(string.ascii_uppercase + string.digits, k=10))


def generate_random_number():
    return str(random.randint(0, 1000000000))


def generate_json(is_fuzzy: bool):
    return {
        "data": {
            "name": generate_random_string(),
            "surname": generate_random_string(),
            "sid": generate_random_number(),
        },
        "keywords": ["name", "surname", "sid"],
        "is_fuzzy": is_fuzzy,
    }


class PseudonymSearch(HttpUser):
    fixed_json = generate_json(is_fuzzy=False)

    @task
    def request_pseudonym(self):
        self.client.post("/requestPseudonym", json=generate_json(is_fuzzy=False))

    @tag("fixed")
    @task
    def request_existing_pseudonym(self):
        self.client.post("/requestPseudonym", json=self.fixed_json)

    @tag("fuzzy")
    @task
    def request_fuzzy_pseudonym(self):
        self.client.post("/requestPseudonym", json=generate_json(is_fuzzy=True))
