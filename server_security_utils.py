from config import clients_db
import hashlib


def authenticate(username, password):
    if username not in clients_db:
        return False
    
    return hashlib.md5(bytes(password, 'utf-8')).digest() == clients_db[username].password_hashed

def get_clients_public_key(username):
    return clients_db[username].public_key

