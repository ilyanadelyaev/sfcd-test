import pytest

import sfcd.logic.common
import sfcd.logic.exc


class TestLogicCommon:
    def test__validate_secret_key(self, config, api_secret_key):
        assert sfcd.logic.common.validate_secret_key(
            config,
            {'secret': api_secret_key}
        ) is None
        #
        with pytest.raises(sfcd.logic.exc.InvalidSecretKey) as ex_info:
            sfcd.logic.common.validate_secret_key(
                config,
                {'secret': 'some_key'},
            )
        assert ex_info.value.message == \
            'Invalid secret key: "some_key"'
        #
        with pytest.raises(sfcd.logic.exc.InvalidSecretKey) as ex_info:
            sfcd.logic.common.validate_secret_key(
                config,
                {},
            )
        assert ex_info.value.message == \
            'Invalid secret key: "None"'
