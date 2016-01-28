import sfcd.misc


class TestCrypto:
    def test__passphrase(self, password):
        hashed, salt = sfcd.misc.Crypto.hash_passphrase(password)
        #
        assert len(hashed) == sfcd.misc.Crypto.hashed_length
        assert len(salt) == sfcd.misc.Crypto.salt_lenght
        #
        assert sfcd.misc.Crypto.validate_passphrase(password, hashed, salt)

    def test__passphrase__empty(self):
        password = ''
        #
        hashed, salt = sfcd.misc.Crypto.hash_passphrase(password)
        #
        assert len(hashed) == sfcd.misc.Crypto.hashed_length
        assert len(salt) == sfcd.misc.Crypto.salt_lenght
        #
        assert sfcd.misc.Crypto.validate_passphrase(password, hashed, salt)

    def test__passphrase__short(self):
        password = 'qwer'
        #
        hashed, salt = sfcd.misc.Crypto.hash_passphrase(password)
        #
        assert len(hashed) == sfcd.misc.Crypto.hashed_length
        assert len(salt) == sfcd.misc.Crypto.salt_lenght
        #
        assert sfcd.misc.Crypto.validate_passphrase(password, hashed, salt)

    def test__passphrase__long(self, password):
        password *= 8
        #
        hashed, salt = sfcd.misc.Crypto.hash_passphrase(password)
        #
        assert len(hashed) == sfcd.misc.Crypto.hashed_length
        assert len(salt) == sfcd.misc.Crypto.salt_lenght
        #
        assert sfcd.misc.Crypto.validate_passphrase(password, hashed, salt)
