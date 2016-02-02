import uuid
import hashlib


class Crypto(object):
    """
    Crypto operations and constants
    """

    hashed_length = 128
    salt_length = 32

    auth_token_length = 64

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

    @staticmethod
    def generate_auth_token():
        return uuid.uuid4().hex + uuid.uuid4().hex
