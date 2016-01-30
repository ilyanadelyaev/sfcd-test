import pytest

import sfcd.misc


class TestCrypto:
    def test__passphrase(self, password):
        hashed, salt = sfcd.misc.Crypto.hash_passphrase(password)
        #
        assert len(hashed) == sfcd.misc.Crypto.hashed_length
        assert len(salt) == sfcd.misc.Crypto.salt_length
        #
        assert sfcd.misc.Crypto.validate_passphrase(password, hashed, salt)

    def test__passphrase__empty(self):
        password = ''
        #
        hashed, salt = sfcd.misc.Crypto.hash_passphrase(password)
        #
        assert len(hashed) == sfcd.misc.Crypto.hashed_length
        assert len(salt) == sfcd.misc.Crypto.salt_length
        #
        assert sfcd.misc.Crypto.validate_passphrase(password, hashed, salt)

    def test__passphrase__short(self):
        password = 'qwer'
        #
        hashed, salt = sfcd.misc.Crypto.hash_passphrase(password)
        #
        assert len(hashed) == sfcd.misc.Crypto.hashed_length
        assert len(salt) == sfcd.misc.Crypto.salt_length
        #
        assert sfcd.misc.Crypto.validate_passphrase(password, hashed, salt)

    def test__passphrase__long(self, password):
        password *= 8
        #
        hashed, salt = sfcd.misc.Crypto.hash_passphrase(password)
        #
        assert len(hashed) == sfcd.misc.Crypto.hashed_length
        assert len(salt) == sfcd.misc.Crypto.salt_length
        #
        assert sfcd.misc.Crypto.validate_passphrase(password, hashed, salt)

    def test__generate_auth_token(self):
        assert len(sfcd.misc.Crypto.generate_auth_token()) == \
            sfcd.misc.Crypto.auth_token_length


class TestRetry:
    def test__no_retry(self):
        @sfcd.misc.retry(Exception, 2)
        def f(v):
            v[0] -= 1
        #
        value = [2]
        f(value)
        # one call without retries
        assert value[0] == 1

    def test__exception_not_match(self):
        @sfcd.misc.retry(AttributeError, 2)
        def f(v):
            v[0] -= 1
            raise RuntimeError
        #
        with pytest.raises(RuntimeError):
            value = [3]
            f(value)
        # one call without retries
        assert value[0] == 2

    def test__0_attempts(self):
        @sfcd.misc.retry(Exception, 0)
        def f(v):
            v[0] -= 1
            raise Exception
        #
        with pytest.raises(Exception):
            value = [1]
            f(value)
        # one call - ignore zero
        assert value[0] == 0

    def test__1_attempt(self):
        @sfcd.misc.retry(Exception, 1)
        def f(v):
            v[0] -= 1
            raise Exception
        #
        with pytest.raises(Exception):
            value = [1]
            f(value)
        # one call
        assert value[0] == 0

    def test__2_attempts(self):
        @sfcd.misc.retry(Exception, 2)
        def f(v):
            v[0] -= 1
            raise Exception
        #
        with pytest.raises(Exception):
            value = [2]
            f(value)
        # two calls
        assert value[0] == 0

    def test__default_attempts(self):
        @sfcd.misc.retry(Exception)
        def f(v):
            v[0] -= 1
            raise Exception
        #
        with pytest.raises(Exception):
            value = [3]
            f(value)
        # three calls
        assert value[0] == 0
