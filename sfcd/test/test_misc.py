import sfcd.misc


class TestMisc:
    def test__hash_password(self, password):
        hashed, salt = sfcd.misc.hash_password(password)
        assert sfcd.misc.validate_password_hash(password, salt, hashed)

