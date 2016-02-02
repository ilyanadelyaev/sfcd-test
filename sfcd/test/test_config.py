import pytest


class TestConfig:
    def test__getattr(self, config):
        assert config.db

    def test__getattr__invalid(self, config):
        with pytest.raises(AttributeError) as ex_info:
            config.moo
        assert ex_info.value.message == \
            "Configuration instance has no attribute 'moo'"
