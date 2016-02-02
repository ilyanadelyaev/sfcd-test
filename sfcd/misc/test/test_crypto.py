import pytest

import sfcd.misc.crypto


class TestCrypto:
    def test__passphrase(self, password):
        hashed, salt = sfcd.misc.crypto.Crypto.hash_passphrase(password)
        #
        assert len(hashed) == sfcd.misc.crypto.Crypto.hashed_length
        assert len(salt) == sfcd.misc.crypto.Crypto.salt_length
        #
        assert sfcd.misc.crypto.Crypto.validate_passphrase(
            password, hashed, salt)

    def test__passphrase__empty(self):
        password = ''
        #
        hashed, salt = sfcd.misc.crypto.Crypto.hash_passphrase(password)
        #
        assert len(hashed) == sfcd.misc.crypto.Crypto.hashed_length
        assert len(salt) == sfcd.misc.crypto.Crypto.salt_length
        #
        assert sfcd.misc.crypto.Crypto.validate_passphrase(
            password, hashed, salt)

    def test__passphrase__short(self):
        password = 'qwer'
        #
        hashed, salt = sfcd.misc.crypto.Crypto.hash_passphrase(password)
        #
        assert len(hashed) == sfcd.misc.crypto.Crypto.hashed_length
        assert len(salt) == sfcd.misc.crypto.Crypto.salt_length
        #
        assert sfcd.misc.crypto.Crypto.validate_passphrase(
            password, hashed, salt)

    def test__passphrase__long(self, password):
        password *= 8
        #
        hashed, salt = sfcd.misc.crypto.Crypto.hash_passphrase(password)
        #
        assert len(hashed) == sfcd.misc.crypto.Crypto.hashed_length
        assert len(salt) == sfcd.misc.crypto.Crypto.salt_length
        #
        assert sfcd.misc.crypto.Crypto.validate_passphrase(
            password, hashed, salt)

    def test__generate_auth_token(self):
        assert len(sfcd.misc.crypto.Crypto.generate_auth_token()) == \
            sfcd.misc.crypto.Crypto.auth_token_length
