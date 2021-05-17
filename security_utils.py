from config import clients_db
from el_gamal_signature import ElGamalSignature
from twofish.twofish_ecb import TwofishECB
import rsa
import hashlib

signature_service = ElGamalSignature()

def authenticate(username, password):
    if username not in clients_db:
        return False
    
    return hashlib.md5(bytes(password, 'utf-8')).digest() == clients_db[username].password_hashed

def get_clients_public_key(username):
    return clients_db[username].public_key

def convert_encrypted_message_to_string(msg):
    return "-".join([str(i) for i in msg])

def sign_message_with_el_gamal(msg):
    # msg should be a string
    return signature_service.sign(msg)

def align_message_to_16_bytes(msg):
    if (len(msg) % 16) == 0:
        return msg
    pad_size = 16 - (len(msg) % 16)
    return msg + " " * pad_size

def convert_encrypted_string_to_message(msg):
    return bytearray([int(num) for num in msg.split('-')])

def sign_and_encrypt_reponse(msg, key):

    msg_aligned = align_message_to_16_bytes(msg)

    msg_in_bytes = bytearray(msg_aligned, 'utf-8')
    encrypted_message = TwofishECB(bytes.fromhex(key)).encrypt(msg_in_bytes)
    encrypted_message_string = convert_encrypted_message_to_string(list(encrypted_message))
    encrypted_message_signature = sign_message_with_el_gamal(encrypted_message_string)
    return encrypted_message_string, encrypted_message_signature

def decrypt_message_in_session(msg, key):
    encrypted_message = convert_encrypted_string_to_message(msg)
    return TwofishECB(bytes.fromhex(key)).decrypt(encrypted_message)

def decrypt_first_message(msg, private_key):
    encrypted_message = [int(num) for num in msg.split('-')]
    return rsa.decrypt(private_key, encrypted_message)
