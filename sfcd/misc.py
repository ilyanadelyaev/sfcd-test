import uuid
import hashlib
import functools


class Crypto(object):
    """
    Crypto operations and constants
    """

    hashed_length = 128
    salt_lenght = 32

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


def retry(exc_cls, tries=3, logger=None):
    """
    Retry decorator
    :exc_cls: class to follow
    :tries: number of tries
    """
    def decoy(f):
        @functools.wraps(f)
        def functor(*args, **kwargs):
            t = tries  # copy
            # last one without catching
            while t > 1:
                try:
                    return f(*args, **kwargs)
                except exc_cls as ex:
                    if logger:
                        msg = 'Retry for "{}" / attempts: {}'.format(
                            f.__name__, (t - 1))
                        logger.error(msg)
                        logger.exception(ex)
                    t -= 1
            return f(*args, **kwargs)
        return functor
    return decoy
