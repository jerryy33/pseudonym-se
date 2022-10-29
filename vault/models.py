from pydantic import BaseModel
from typing import List


class SearchRequest(BaseModel):
    user_id: int
    queries: List[List[str]]
    is_fuzzy: bool
    expected_amount_of_keywords: int


class AddRequest(BaseModel):
    record: str
    indices: List[List]
