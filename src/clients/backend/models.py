"""Models used for API"""
from typing import Dict, List
from pydantic import BaseModel


class PseudonymRequest(BaseModel):
    """Model for a pseudonymm request, contains the actual data a list of keywords and
    if a search should be fuzzy or not"""

    data: Dict[str, str]
    keywords: List[str]
    is_fuzzy: bool


class SecurityDetails(BaseModel):
    """Data which will be send by the user-manager"""

    query_key: bytes
    seed: bytes
    encryption_key: bytes
    user_id: int
