import os
from dotenv import load_dotenv
from charm.toolbox.pairinggroup import PairingGroup


load_dotenv()

API_DB = os.environ.get("API_DB")
PSEUDONYM_ENTRIES = os.environ.get("PSEUDONYM_ENTRIES")
GROUP = PairingGroup(os.environ.get("PAIRING_GROUP"))
