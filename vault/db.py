""""""
import urllib.parse
import redis
from constants import API_DB

db = urllib.parse.urlsplit(API_DB)
database = redis.Redis(host=db.hostname, port=db.port, db=0, decode_responses=True)
