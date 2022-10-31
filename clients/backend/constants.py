"""Global constants"""
import os
from dotenv import load_dotenv
from charm.toolbox.pairinggroup import PairingGroup

load_dotenv()

CLIENT_DB = os.environ.get("CLIENT_DB")
MY_ID = int(os.environ.get("CLIENT_ID"))
API_URL = os.environ.get("API_URL")
UM_URL = os.environ.get("USER_MANAGER_URL")
GROUP = PairingGroup(os.environ.get("PAIRING_GROUP"))
