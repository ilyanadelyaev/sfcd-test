import uuid
import hashlib


class Crypto(object):
    """
    Crypto operations and constants
    """

    hashed_length = 128
    salt_lenght = 32

    @staticmethod
    def hash_passphrase(passphrase):
        """
        Generates salt and return hashed value for passphrase
        """
        salt = uuid.uuid4().hex
        return (hashlib.sha512(passphrase + salt).hexdigest(), salt)

    @staticmethod
    def validate_passphrase(passphrase, hashed, salt):
        """
        Validate user passphrase with stored hashed value and salt
        """
        return hashlib.sha512(passphrase + salt).hexdigest() == hashed
