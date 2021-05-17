import random


class Client:
    def __init__(self, name, password_hashed, rsa_key_pair):
        self.name = name
        self.password_hashed = password_hashed
        self.public_key = rsa_key_pair[0]
        self.private_key = rsa_key_pair[1]
