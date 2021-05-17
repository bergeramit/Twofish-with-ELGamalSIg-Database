from Crypto.Util.number import *
from Crypto import Random
import Crypto
import libnum
import sys
from random import randint
import hashlib

class ElGamalSignature:

    def __init__(self, bits=60):
        self.bits = bits
        self.q = Crypto.Util.number.getPrime(self.bits, randfunc=Crypto.Random.get_random_bytes)
        self.a = 2
        self.x_a = randint(0, self.q-1)

    def sign(self, msg):
        h_msg = int.from_bytes(hashlib.sha256(msg.encode()).digest(), byteorder='big')
        K = Crypto.Util.number.getPrime(self.bits, randfunc=Crypto.Random.get_random_bytes)
        # e_1=(gmpy2.invert(e, p-1))
        K_1 = (libnum.invmod(K, self.q-1))

        S_1=pow(self.a, K, self.q)
        S_2=((h_msg-self.x_a * S_1) * K_1) % (self.q-1)

        return (S_1, S_2)

    def verify(self, S_1, S_2, encrypted_message):
        h_msg = int.from_bytes(hashlib.sha256(encrypted_message.encode()).digest(), byteorder='big')
        v = pow(self.a, self.x_a, self.q)
        v_1 = (pow(v,S_1, self.q) * pow(S_1,S_2,self.q)) % self.q
        v_2 = pow(self.a, h_msg, self.q)
        assert v_1 == v_2
        return v_1, v_2


def test_el_gamal_signature():
    msg = "Hello"
    print(f"Message to sign: {msg}")
    sig = ElGamalSignature(msg)
    S_1, S_2 = sig.sign()
    print(f"S_1 = {S_1}, S_2 = {S_2}")
    print("Checking the signature...")

    v_1, v_2 = sig.verify(S_1, S_2)
    print(f"S_1 = {v_1}, S_2 = {v_2}")
    print("Same Same :)")


if __name__ == "__main__":
    test_el_gamal_signature()