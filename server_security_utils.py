from config import clients_db, SERVER_TWOFISH_SYMETRIC_KEY_PLAINTEXT
from el_gamal_signature import ElGamalSignature
from twofish.twofish_ecb import TwofishECB
import hashlib


def authenticate(username, password):
    if username not in clients_db:
        return False
    
    return hashlib.md5(bytes(password, 'utf-8')).digest() == clients_db[username].password_hashed

def get_clients_public_key(username):
    return clients_db[username].public_key

def _convert_encrypted_message_to_string(msg):
    return "".join([str(i) for i in msg])

def sign_message_with_el_gamal(msg):
    # msg should be a list of ints (i.e [1, 2323, 20])
    return ElGamalSignature(_convert_encrypted_message_to_string(msg)).sign()

def align_message_to_16_bytes(msg):
    if (len(msg) % 16) == 0:
        return msg
    pad_size = 16 - (len(msg) % 16)
    return msg + " " * pad_size

def sign_and_encrypt_reponse(msg):

    msg_aligned = align_message_to_16_bytes(msg)

    msg_in_bytes = bytearray(msg_aligned, 'utf-8')
    encrypted_message = TwofishECB(bytes.fromhex(SERVER_TWOFISH_SYMETRIC_KEY_PLAINTEXT)).encrypt(msg_in_bytes)
    encrypted_message_signature = sign_message_with_el_gamal(list(encrypted_message))
    return encrypted_message, encrypted_message_signature

def decrypt_user_message(msg):
    return TwofishECB(bytes.fromhex(SERVER_TWOFISH_SYMETRIC_KEY_PLAINTEXT)).decrypt(msg)
