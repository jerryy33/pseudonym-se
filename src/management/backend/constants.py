"""Global constants"""
import os
import ast
from typing import List
from dotenv import load_dotenv
from charm.toolbox.pairinggroup import PairingGroup

load_dotenv()

GROUP = PairingGroup(os.environ.get("PAIRING_GROUP"))
CLIENT_URL_LIST: List = ast.literal_eval(os.environ.get("CLIENT_URL_ID_DICT"))
API_URL = os.environ.get("API_URL")
USER_MANAGER_DB = os.environ.get("USER_MANAGER_DB")
UA = "Authorized-Users-IDs"
UR = "Revoked-User-IDs"
