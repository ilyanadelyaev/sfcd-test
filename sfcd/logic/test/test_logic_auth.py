import pytest

import sfcd.logic.auth


@pytest.fixture(scope='session')
def auth_logic(db_engine):
    return sfcd.logic.auth.AuthLogic(db_engine)


class TestLogicAuth:
    def test__validate_email(self, auth_logic, email, email_2):
        assert auth_logic._validate_email(email) is None
        assert auth_logic._validate_email(email_2) is None
        assert auth_logic._validate_email('me@example.com') is None
        assert auth_logic._validate_email('me.and.you@example.com') is None
        #
        with pytest.raises(sfcd.logic.auth.InvalidArgument) as ex_info:
            auth_logic._validate_email('example')
        assert ex_info.value.message == \
            'Ivalid argument {} = "{}"'.format('email', 'example')
        with pytest.raises(sfcd.logic.auth.InvalidArgument) as ex_info:
            auth_logic._validate_email('example.com')
        assert ex_info.value.message == \
            'Ivalid argument {} = "{}"'.format('email', 'example.com')
        with pytest.raises(sfcd.logic.auth.InvalidArgument) as ex_info:
            auth_logic._validate_email('@example.com')
        assert ex_info.value.message == \
            'Ivalid argument {} = "{}"'.format('email', '@example.com')
        with pytest.raises(sfcd.logic.auth.InvalidArgument) as ex_info:
            auth_logic._validate_email('.@example.com')
        assert ex_info.value.message == \
            'Ivalid argument {} = "{}"'.format('email', '.@example.com')

    def test__validate_simple(self, auth_logic, password):
        assert auth_logic._validate_simple(password) is None
        #
        with pytest.raises(sfcd.logic.auth.InvalidArgument) as ex_info:
            auth_logic._validate_simple(None)
        assert ex_info.value.message == \
            'Ivalid argument {} = "{}"'.format('password', None)

    def test__validate_facebook(
            self, auth_logic, facebook_id, facebook_token
    ):
        assert auth_logic._validate_facebook(
            facebook_id, facebook_token
        ) is None
        #
        with pytest.raises(sfcd.logic.auth.InvalidArgument) as ex_info:
            auth_logic._validate_facebook('', facebook_token)
        assert ex_info.value.message == \
            'Ivalid argument {} = "{}"'.format('facebook_id', '')
        with pytest.raises(sfcd.logic.auth.InvalidArgument) as ex_info:
            auth_logic._validate_facebook(facebook_id, None)
        assert ex_info.value.message == \
            'Ivalid argument {} = "{}"'.format('facebook_token', None)

    def test__signup__invalid_input_data(self, auth_logic):
        """
        check for empty input
        """
        with pytest.raises(sfcd.logic.auth.RegistrationError) as ex_info:
            auth_logic.signup(None)
        assert ex_info.value.message == \
            'Registration error with: "empty data"'
        with pytest.raises(sfcd.logic.auth.RegistrationError) as ex_info:
            auth_logic.signup({})
        assert ex_info.value.message == \
            'Registration error with: "empty data"'

    def test__signup__ivalid_auth_type(
            self, auth_logic, api_secret_key,
            email, password
    ):
        with pytest.raises(sfcd.logic.auth.InvalidAuthType) as ex_info:
            auth_logic.signup({
                'secret': api_secret_key,
                'email': email,
                'type': 'invalid',
            })
        assert ex_info.value.message == \
            'Invalid auth type: "invalid"'

    def test__signup__simple__invalid_args(
            self, auth_logic, api_secret_key, email, password
    ):
        # invalid email
        with pytest.raises(sfcd.logic.auth.InvalidArgument) as ex_info:
            auth_logic.signup({
                'secret': api_secret_key,
                'type': 'simple',
                'email': 'invalid',
                'password': password,
            })
        assert ex_info.value.message == \
            'Ivalid argument {} = "{}"'.format('email', 'invalid')
        # invalid password
        with pytest.raises(sfcd.logic.auth.InvalidArgument) as ex_info:
            auth_logic.signup({
                'secret': api_secret_key,
                'type': 'simple',
                'email': email,
                'password': None,
            })
        assert ex_info.value.message == \
            'Ivalid argument {} = "{}"'.format('password', None)

    def test__signup__facebook__invalid_args(
            self, auth_logic, api_secret_key,
            email, facebook_id, facebook_token
    ):
        # invalid email
        with pytest.raises(sfcd.logic.auth.InvalidArgument) as ex_info:
            auth_logic.signup({
                'secret': api_secret_key,
                'type': 'facebook',
                'email': 'invalid',
                'facebook_id': facebook_id,
                'facebook_token': facebook_token,
            })
        assert ex_info.value.message == \
            'Ivalid argument {} = "{}"'.format('email', 'invalid')
        # invalid facebook_id
        with pytest.raises(sfcd.logic.auth.InvalidArgument) as ex_info:
            auth_logic.signup({
                'secret': api_secret_key,
                'type': 'facebook',
                'email': email,
                'facebook_id': '',
                'facebook_token': facebook_token,
            })
        assert ex_info.value.message == \
            'Ivalid argument {} = "{}"'.format('facebook_id', '')
        # invalid facebook_token
        with pytest.raises(sfcd.logic.auth.InvalidArgument) as ex_info:
            auth_logic.signup({
                'secret': api_secret_key,
                'type': 'facebook',
                'email': email,
                'facebook_id': facebook_id,
                'facebook_token': None,
            })
        assert ex_info.value.message == \
            'Ivalid argument {} = "{}"'.format('facebook_token', None)
        # no facebook args
        with pytest.raises(sfcd.logic.auth.InvalidArgument) as ex_info:
            auth_logic.signup({
                'secret': api_secret_key,
                'type': 'facebook',
                'email': email,
            })
        assert ex_info.value.message == \
            'Ivalid argument {} = "{}"'.format('facebook_id', None)

    def test__signup__facebook__facebook_id_exitsts(
            self, auth_logic, api_secret_key,
            email, email_2, facebook_id, facebook_token
    ):
        auth_logic.signup({
            'secret': api_secret_key,
            'type': 'facebook',
            'email': email,
            'facebook_id': facebook_id,
            'facebook_token': facebook_token,
        })
        #
        with pytest.raises(sfcd.logic.auth.RegistrationError) as ex_info:
            auth_logic.signup({
                'secret': api_secret_key,
                'type': 'facebook',
                'email': email_2,
                'facebook_id': facebook_id,
                'facebook_token': facebook_token,
            })
        assert ex_info.value.message == \
            'Registration error with: "facebook_id "{}" exists"'.format(
                facebook_id)

    def test__signup__already_exists(
            self, db_engine, auth_logic, api_secret_key, email, password
    ):
        db_engine.auth.register_simple_auth(email, password)
        #
        with pytest.raises(sfcd.logic.auth.RegistrationError) as ex_info:
            auth_logic.signup({
                'secret': api_secret_key,
                'type': 'simple',
                'email': email,
                'password': password,
            })
        assert ex_info.value.message == \
            'Registration error with: "email "{}" exists"'.format(email)

    def test__signup__simple(
            self, db_engine, auth_logic, api_secret_key, email, password
    ):
        assert not db_engine.auth.email_exists(email)
        #
        auth_logic.signup({
            'secret': api_secret_key,
            'type': 'simple',
            'email': email,
            'password': password,
        })
        #
        assert db_engine.auth.email_exists(email)

    def test__signup__facebook(
            self, db_engine, auth_logic, api_secret_key,
            email, facebook_id, facebook_token
    ):
        assert not db_engine.auth.email_exists(email)
        #
        auth_logic.signup({
            'secret': api_secret_key,
            'type': 'facebook',
            'email': email,
            'facebook_id': facebook_id,
            'facebook_token': facebook_token,
        })
        #
        assert db_engine.auth.email_exists(email)

    def test__signin__invalid_input_data(self, auth_logic):
        """
        check for empty input
        """
        with pytest.raises(sfcd.logic.auth.LoginError) as ex_info:
            auth_logic.signin(None)
        assert ex_info.value.message == \
            'Login error with: "empty data"'
        with pytest.raises(sfcd.logic.auth.LoginError) as ex_info:
            auth_logic.signin({})
        assert ex_info.value.message == \
            'Login error with: "empty data"'

    def test__signin__not_exists(self, auth_logic, api_secret_key, email):
        with pytest.raises(sfcd.logic.auth.LoginError) as ex_info:
            auth_logic.signin({
                'secret': api_secret_key,
                'type': 'simple',
                'email': email,
                'password': '',
            })
        assert ex_info.value.message == \
            'Login error with: "email "{}" not exists"'.format(email)

    def test__signin__ivalid_auth_type(
            self, db_engine, auth_logic, api_secret_key,
            email, password
    ):
        # create record
        db_engine.auth.register_simple_auth(email, password)
        #
        with pytest.raises(sfcd.logic.auth.InvalidAuthType) as ex_info:
            auth_logic.signin({
                'secret': api_secret_key,
                'email': email,
                'type': 'invalid',
            })
        assert ex_info.value.message == 'Invalid auth type: "invalid"'

    def test__signin__simple__invalid_args(
            self, db_engine, auth_logic, api_secret_key,
            email, password
    ):
        # create record
        db_engine.auth.register_simple_auth(email, password)
        # invalid email
        with pytest.raises(sfcd.logic.auth.InvalidArgument) as ex_info:
            auth_logic.signin({
                'secret': api_secret_key,
                'type': 'simple',
                'email': 'invalid',
            })
        assert ex_info.value.message == \
            'Ivalid argument {} = "{}"'.format('email', 'invalid')
        # none password
        with pytest.raises(sfcd.logic.auth.InvalidArgument) as ex_info:
            auth_logic.signin({
                'secret': api_secret_key,
                'type': 'simple',
                'email': email,
                'password': None
            })
        assert ex_info.value.message == \
            'Ivalid argument {} = "{}"'.format('password', None)
        # no password
        with pytest.raises(sfcd.logic.auth.InvalidArgument) as ex_info:
            auth_logic.signin({
                'secret': api_secret_key,
                'type': 'simple',
                'email': email,
            })
        assert ex_info.value.message == \
            'Ivalid argument {} = "{}"'.format('password', None)

    def test__signin__facebook__invalid_args(
            self, db_engine, auth_logic, api_secret_key,
            email, facebook_id, facebook_token
    ):
        # create record
        db_engine.auth.register_facebook_auth(
            email, facebook_id, facebook_token)
        # invalid email
        with pytest.raises(sfcd.logic.auth.InvalidArgument) as ex_info:
            auth_logic.signin({
                'secret': api_secret_key,
                'type': 'facebook',
                'email': 'invalid',
            })
        assert ex_info.value.message == \
            'Ivalid argument {} = "{}"'.format('email', 'invalid')
        # none facebook
        with pytest.raises(sfcd.logic.auth.InvalidArgument) as ex_info:
            auth_logic.signin({
                'secret': api_secret_key,
                'type': 'facebook',
                'email': email,
                'facebook_id': '',
                'facebook_token': '',
            })
        assert ex_info.value.message == \
            'Ivalid argument {} = "{}"'.format('facebook_id', '')
        # no facebook params
        with pytest.raises(sfcd.logic.auth.InvalidArgument) as ex_info:
            auth_logic.signin({
                'secret': api_secret_key,
                'type': 'facebook',
                'email': email,
                'facebook_id': facebook_id,
            })
        assert ex_info.value.message == \
            'Ivalid argument {} = "{}"'.format('facebook_token', None)

    def test__signin__simple(
            self, db_engine, auth_logic, api_secret_key,
            email, password
    ):
        # create record
        db_engine.auth.register_simple_auth(email, password)
        #
        token = auth_logic.signin({
            'secret': api_secret_key,
            'type': 'simple',
            'email': email,
            'password': password,
        })
        #
        token_db = db_engine.auth.get_token_simple_auth(
            email, password)
        #
        assert len(token) == sfcd.misc.Crypto.auth_token_length
        assert token == token_db

    def test__signin__simple__equal_tokens(
            self, db_engine, auth_logic, api_secret_key,
            email, password
    ):
        # create record
        db_engine.auth.register_simple_auth(email, password)
        #
        token_1 = auth_logic.signin({
            'secret': api_secret_key,
            'type': 'simple',
            'email': email,
            'password': password,
        })
        token_2 = auth_logic.signin({
            'secret': api_secret_key,
            'type': 'simple',
            'email': email,
            'password': password,
        })
        assert len(token_1) == sfcd.misc.Crypto.auth_token_length
        assert token_1 == token_2

    def test__signin__facebook(
            self, db_engine, auth_logic, api_secret_key,
            email, facebook_id, facebook_token
    ):
        # create record
        db_engine.auth.register_facebook_auth(
            email, facebook_id, facebook_token)
        #
        token = auth_logic.signin({
            'secret': api_secret_key,
            'type': 'facebook',
            'email': email,
            'facebook_id': facebook_id,
            'facebook_token': facebook_token,
        })
        #
        token_db = db_engine.auth.get_token_facebook_auth(
            email, facebook_id, facebook_token)
        #
        assert len(token) == sfcd.misc.Crypto.auth_token_length
        assert token == token_db

    def test__signin__facebook__equal_tokens(
            self, db_engine, auth_logic, api_secret_key,
            email, facebook_id, facebook_token
    ):
        # create record
        db_engine.auth.register_facebook_auth(
            email, facebook_id, facebook_token)
        #
        token_1 = auth_logic.signin({
            'secret': api_secret_key,
            'type': 'facebook',
            'email': email,
            'facebook_id': facebook_id,
            'facebook_token': facebook_token,
        })
        token_2 = auth_logic.signin({
            'secret': api_secret_key,
            'type': 'facebook',
            'email': email,
            'facebook_id': facebook_id,
            'facebook_token': facebook_token,
        })
        assert len(token_1) == sfcd.misc.Crypto.auth_token_length
        assert token_1 == token_2

    def test__signup_signin__simple(
            self, auth_logic, api_secret_key,
            email, password
    ):
        # signup
        assert auth_logic.signup({
            'secret': api_secret_key,
            'type': 'simple',
            'email': email,
            'password': password,
        }) is None
        # signin - some token
        assert auth_logic.signin({
            'secret': api_secret_key,
            'type': 'simple',
            'email': email,
            'password': password,
        })

    def test__signup_signin__facebook(
        self, db_engine, auth_logic, api_secret_key,
        email, facebook_id, facebook_token
    ):
        # signup
        assert auth_logic.signup({
            'secret': api_secret_key,
            'type': 'facebook',
            'email': email,
            'facebook_id': facebook_id,
            'facebook_token': facebook_token,
        }) is None
        # signin - some token
        assert auth_logic.signin({
            'secret': api_secret_key,
            'type': 'facebook',
            'email': email,
            'facebook_id': facebook_id,
            'facebook_token': facebook_token,
        })
