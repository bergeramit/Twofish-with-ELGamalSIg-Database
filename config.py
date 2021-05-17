import hashlib
import time
import struct
import rsa
from client import Client

MENU = '''
    [1] for uploading new table entry
    [2] get entry from table
'''

clients_db = {
    "amit": Client("amit", hashlib.md5(b"1234").digest(), rsa.generate_key_pair(p=17, q=19)),
    "yaniv": Client("yaniv", hashlib.md5(b"2345").digest(), rsa.generate_key_pair(p=17, q=19)),
    "or": Client("amit", hashlib.md5(b"aaaa").digest(), rsa.generate_key_pair(p=17, q=19)),
    "justin": Client("amit", hashlib.md5(b"bbbb").digest(), rsa.generate_key_pair(p=17, q=19)),
}

def _generate_twofish_symetric_key_object():
    return hashlib.md5(struct.pack(">i", int(time.time()))).hexdigest()

SERVER_TWOFISH_SYMETRIC_KEY_PLAINTEXT = _generate_twofish_symetric_key_object()
