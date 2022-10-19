import urllib.parse
import redis
from constants import CLIENT_DB

db = urllib.parse.urlsplit(CLIENT_DB)
DB = redis.Redis(host=db.hostname, port=db.port, db=0, decode_responses=True)
