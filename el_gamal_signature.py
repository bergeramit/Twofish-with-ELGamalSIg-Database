# https://asecuritysite.com/encryption/el_sig
from Crypto.Util.number import *
from Crypto import Random
import Crypto
import libnum
import sys
from random import randint
import hashlib

class ElGamalSig:

    def __init__(self, msg, bits=60):
        self.bits = bits
        self.p = Crypto.Util.number.getPrime(self.bits, randfunc=Crypto.Random.get_random_bytes)
        self.g = 2
        self.s = randint(0, self.p-1)
        self.D = int.from_bytes(hashlib.sha256(msg.encode()).digest(), byteorder='big')

    def sign(self):
        e = Crypto.Util.number.getPrime(self.bits, randfunc=Crypto.Random.get_random_bytes)
        # e_1=(gmpy2.invert(e, p-1))
        e_1 = (libnum.invmod(e, self.p-1))

        S_1=pow(self.g, e, self.p)
        S_2=((self.D-self.s*S_1)*e_1) % (self.p-1)

        return (S_1, S_2)

    def verify(self, S_1, S_2):
        v = pow(self.g, self.s, self.p)
        v_1 = (pow(v,S_1, self.p) * pow(S_1,S_2,self.p)) % self.p
        v_2 = pow(self.g, self.D, self.p)
        assert v_1 == v_2
        return v_1, v_2


def test_el_gamal_signature():
    sig = ElGamalSig("Hello")
    S_1, S_2 = sig.sign()
    print(f"S_1 = {S_1}, S_2 = {S_2}")
    print("Checking the signature...")

    v_1, v_2 = sig.verify(S_1, S_2)
    print(f"S_1 = {v_1}, S_2 = {v_2}")
    print("Same Same :)")


if __name__ == "__main__":
    test_el_gamal_signature()