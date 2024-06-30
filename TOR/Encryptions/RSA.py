# Libraries
from Crypto.Util.number import getStrongPrime


# Classes
class public_key:
    """
    A public key for the RSA
    Fields:
        * e (int): The public exponent
        * n (int): The public modulus
    """

    def __init__(self, e: int, n: int):
        self.__e = e
        self.__n = n

    def get_e(self) -> int:
        return self.__e

    def get_n(self) -> int:
        return self.__n


class private_key:
    """
    A private key for the RSA
    Fields:
        * d (int): The private exponent
        * n (int): The public modulus
    """

    def __init__(self, d: int, n: int):
        self.__d = d
        self.__n = n

    def get_d(self) -> int:
        return self.__d

    def get_n(self) -> int:
        return self.__n


class rsa:
    """
    An implementation of the RSA crypto-system.
    This class provides methods for generating key pairs, encrypting and decrypting messages.

    Fields:
        * p (int): Strong secret first prime
        * q (int): Strong secret second prime
        * n (int): p * q (modulus)
        * phi (int): Euler function of (p * q)
        * e (int): public exponent
        * d (int): private exponent
    """

    PUBLIC_EXPONENT = 65537

    def __init__(self):
        self.__p = getStrongPrime(2048)
        self.__q = getStrongPrime(2048)

        self.__n = self.__p * self.__q
        self.__phi = (self.__p - 1) * (self.__q - 1)

        self.__e = rsa.PUBLIC_EXPONENT
        self.__d = rsa.__modular_inverse(self.__e, self.__phi)

    def get_public_key(self) -> public_key:
        """
        The public key is a tuple (public exponent, public modulus).
        :return: The public key for this RSA key pair
        """
        return public_key(self.__e, self.__n)

    def get_private_key(self) -> private_key:
        """
        The public key is a tuple (private exponent, public modulus).
        :return: The private key for this RSA key pair
        """
        return private_key(self.__d, self.__n)

    @staticmethod
    def encrypt(plain_number: int, current_public_key: public_key) -> int:
        """
        Encrypts a message using the given public key.
        The message is encrypted using the following steps:

        1. Convert the message to an integer using big-endian encoding.
        2. Compute the ciphertext as `c = m^e (mod n)` where:
            * m is the message integer
            * e is the public exponent
            * n is the public modulus
        :param plain_number: the number to encrypt
        :param current_public_key: the public key to use for encryption
        :return: The ciphertext
        """
        if not isinstance(current_public_key, public_key):
            raise ValueError('Not public key given')

        return pow(plain_number, current_public_key.get_e(), current_public_key.get_n())

    @staticmethod
    def decrypt(encrypted_number: int, current_private_key: private_key) -> int:
        """
        Decrypts a ciphertext using the given private key.
        The ciphertext is decrypted using the following steps:

        1. Compute the decrypted message as `m = c^d (mod n)` where:
            * c is the ciphertext
            * d is the private exponent
            * n is the public modulus
        2. Convert the decrypted message to a string using big-endian encoding
        :param encrypted_number: the encrypted number to decrypt
        :param current_private_key: the private key to use for decryption
        :return: The plaintext message
        """
        if not isinstance(current_private_key, private_key):
            raise ValueError('Not private key given')

        return pow(encrypted_number, current_private_key.get_d(), current_private_key.get_n())

    # Helper methods
    @staticmethod
    def __modular_inverse(e: int, phi: int) -> int:
        """
        Function calculate d (private exponent) using the Extended Euclidean Algorithm
        :param e: RSA public exponent
        :param phi: Euler function of two big primes (p and g)
        :return: private exponent from RSA - d
        """
        if rsa.__gcd(e, phi) != 1:
            return -1  # d doesn't exist

        g, x, _ = rsa.__extended_gcd(e, phi)
        d = x % phi
        return d

    @staticmethod
    def __gcd(a: int, b: int) -> int:
        """
        Function calculates the greatest common factor number that divides them
        :param a: the first integer
        :param b: the second integer
        :return: greatest common divider of a and b
        """
        while b:
            a, b = b, a % b
        return a

    @staticmethod
    def __extended_gcd(a: int, b: int) -> tuple:
        """
        Function computes the extended greatest common divisor (GCD) of two integers a and b.
        The extended GCD of a and b is a tuple (g, x, y) such that:
            * g = gcd(a, b)
            * ax + by = g
        In other words, x and y are coefficients such that the linear combination of a and b equals their GCD
        :param a: the first integer
        :param b: the second integer
        :return: a tuple (g, x, y) such that g = gcd(a, b) and ax + by = g.
        """
        if a == 0:
            return b, 0, 1

        g, x, y = rsa.__extended_gcd(b % a, a)
        return g, (y - (b // a) * x), x
