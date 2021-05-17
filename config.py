import hashlib
import rsa
from client import Client

clients_db = {
    "amit": Client("amit", hashlib.md5(b"1234").digest(), rsa.generate_key_pair(p=17, q=19)),
    "yaniv": Client("yaniv", hashlib.md5(b"2345").digest(), rsa.generate_key_pair(p=17, q=19)),
    "or": Client("amit", hashlib.md5(b"aaaa").digest(), rsa.generate_key_pair(p=17, q=19)),
    "justin": Client("amit", hashlib.md5(b"bbbb").digest(), rsa.generate_key_pair(p=17, q=19)),
}