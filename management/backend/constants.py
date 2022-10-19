import os
from dotenv import load_dotenv
from charm.toolbox.pairinggroup import PairingGroup

load_dotenv()

GROUP = PairingGroup(os.environ.get("PAIRING_GROUP"))
CLIENT_URL = os.environ.get("CLIENT_BACKEND_URL")
API_URL = os.environ.get("API_URL")
USER_MANAGER_DB = os.environ.get("USER_MANAGER_DB")
UA = "Authorized-Users-IDs"
UR = "Revoked-User-IDs"
