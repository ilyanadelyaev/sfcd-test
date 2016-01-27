import pytest

import sfcd.logic.auth


@pytest.fixture(scope='session')
def auth_logic(db_engine):
    return sfcd.logic.auth.AuthLogic(db_engine)


class TestAuthLogic:
    def test__check_secret(self, auth_logic, api_secret_key):
        assert auth_logic._check_secret({'secret': api_secret_key}) is None
        with pytest.raises(sfcd.logic.auth.InvalidSecretKey) as ex:
            auth_logic._check_secret({'secret': 'some key'})
            assert ex.value == 'some key'
        with pytest.raises(sfcd.logic.auth.InvalidSecretKey) as ex:
            auth_logic._check_secret({})
            assert ex.value is None

    def test__validate_email(self, auth_logic, email, email_2):
        assert auth_logic._validate_email(email) is None
        assert auth_logic._validate_email(email_2) is None
        assert auth_logic._validate_email('me@example.com') is None
        assert auth_logic._validate_email('me.and.you@example.com') is None
        #
        with pytest.raises(sfcd.logic.auth.InvalidArgument) as ex:
            auth_logic._validate_email('example')
            assert ex.value == ('email', 'example')
        with pytest.raises(sfcd.logic.auth.InvalidArgument) as ex:
            auth_logic._validate_email('example.com')
            assert ex.value == ('email', 'example.com')
        with pytest.raises(sfcd.logic.auth.InvalidArgument) as ex:
            auth_logic._validate_email('@example.com')
            assert ex.value == ('email', '@example.com')
        with pytest.raises(sfcd.logic.auth.InvalidArgument) as ex:
            auth_logic._validate_email('.@example.com')
            assert ex.value == ('email', '.@example.com')

    def test__validate_simple(self, auth_logic, password):
        assert auth_logic._validate_simple(password) is None
        #
        with pytest.raises(sfcd.logic.auth.InvalidArgument) as ex:
            auth_logic._validate_simple(None)
            assert ex.value == ('password', None)

    def test__validate_facebook(
            self, auth_logic, facebook_id, facebook_token
    ):
        assert auth_logic._validate_facebook(
            facebook_id, facebook_token
        ) is None
        #
        with pytest.raises(sfcd.logic.auth.InvalidArgument) as ex:
            auth_logic._validate_facebook('', facebook_token)
            assert ex.value('facebook_id', '')
        with pytest.raises(sfcd.logic.auth.InvalidArgument) as ex:
            auth_logic._validate_facebook(facebook_id, None)
            assert ex.value('facebook_token', None)

    def test__signup__ivalid_auth_type(
            self, auth_logic, api_secret_key,
            email, password
    ):
        with pytest.raises(sfcd.logic.auth.InvalidAuthType) as ex:
            auth_logic.signup({
                'secret': api_secret_key,
                'email': email,
                'type': 'invalid',
            })
            assert ex.value == 'invalid'

    def test__signup__simple__invalid_args(
            self, auth_logic, api_secret_key, email, password
    ):
        # invalid email
        with pytest.raises(sfcd.logic.auth.InvalidArgument) as ex:
            auth_logic.signup({
                'secret': api_secret_key,
                'type': 'simple',
                'email': 'invalid',
                'password': password,
            })
            assert ex.value == ('email', 'ivalid')
        # invalid password
        with pytest.raises(sfcd.logic.auth.InvalidArgument) as ex:
            auth_logic.signup({
                'secret': api_secret_key,
                'type': 'simple',
                'email': email,
                'password': None,
            })
            assert ex.value == ('password', None)

    def test__signup__facebook__invalid_args(
            self, auth_logic, api_secret_key,
            email, facebook_id, facebook_token
    ):
        # invalid email
        with pytest.raises(sfcd.logic.auth.InvalidArgument) as ex:
            auth_logic.signup({
                'secret': api_secret_key,
                'type': 'facebook',
                'email': 'invalid',
                'facebook_id': facebook_id,
                'facebook_token': facebook_token,
            })
            assert ex.value == ('email', 'ivalid')
        # invalid facebook_id
        with pytest.raises(sfcd.logic.auth.InvalidArgument) as ex:
            auth_logic.signup({
                'secret': api_secret_key,
                'type': 'facebook',
                'email': email,
                'facebook_id': '',
                'facebook_token': facebook_token,
            })
            assert ex.value == ('facebook_id', '')
        # invalid facebook_token
        with pytest.raises(sfcd.logic.auth.InvalidArgument) as ex:
            auth_logic.signup({
                'secret': api_secret_key,
                'type': 'facebook',
                'email': email,
                'facebook_id': facebook_id,
                'facebook_token': None,
            })
            assert ex.value == ('facebook_token', None)
        # no facebook args
        with pytest.raises(sfcd.logic.auth.InvalidArgument) as ex:
            auth_logic.signup({
                'secret': api_secret_key,
                'type': 'facebook',
                'email': email,
            })
            assert ex.value == ('facebook_id', None)

    def test__signup__already_exists(
            self, db_engine, auth_logic, api_secret_key, email, password
    ):
        db_engine.auth.add_simple_auth(email, password)
        #
        with pytest.raises(sfcd.logic.auth.AlreadyRegistered) as ex:
            auth_logic.signup({
                'secret': api_secret_key,
                'type': 'simple',
                'email': email,
                'password': password,
            })
            assert ex.value == email

    def test__signup__simple(
            self, db_engine, auth_logic, api_secret_key, email, password
    ):
        assert not db_engine.auth.auth_exists(email)
        #
        auth_logic.signup({
            'secret': api_secret_key,
            'type': 'simple',
            'email': email,
            'password': password,
        })
        #
        assert db_engine.auth.auth_exists(email)

    def test__signup__facebook(
            self, db_engine, auth_logic, api_secret_key,
            email, facebook_id, facebook_token
    ):
        assert not db_engine.auth.auth_exists(email)
        #
        auth_logic.signup({
            'secret': api_secret_key,
            'type': 'facebook',
            'email': email,
            'facebook_id': facebook_id,
            'facebook_token': facebook_token,
        })
        #
        assert db_engine.auth.auth_exists(email)

    def test__signin__not_exists(self, auth_logic, api_secret_key, email):
        with pytest.raises(sfcd.logic.auth.LoginError):
            auth_logic.signin({
                'secret': api_secret_key,
                'type': 'simple',
                'email': email,
            })

    def test__signin__ivalid_auth_type(
            self, db_engine, auth_logic, api_secret_key,
            email, password
    ):
        # create record
        db_engine.auth.add_simple_auth(email, password)
        #
        with pytest.raises(sfcd.logic.auth.InvalidAuthType) as ex:
            auth_logic.signin({
                'secret': api_secret_key,
                'email': email,
                'type': 'invalid',
            })
            assert ex.value == 'invalid'

    def test__signin__simple__invalid_args(
            self, db_engine, auth_logic, api_secret_key,
            email, password
    ):
        # create record
        db_engine.auth.add_simple_auth(email, password)
        # invalid email
        with pytest.raises(sfcd.logic.auth.InvalidArgument) as ex:
            auth_logic.signin({
                'secret': api_secret_key,
                'type': 'simple',
                'email': 'invalid',
            })
            ex.value == ('email', 'invalid')
        # none password
        with pytest.raises(sfcd.logic.auth.InvalidArgument) as ex:
            auth_logic.signin({
                'secret': api_secret_key,
                'type': 'simple',
                'email': email,
                'password': None
            })
            ex.value == ('password', None)
        # no password
        with pytest.raises(sfcd.logic.auth.InvalidArgument) as ex:
            auth_logic.signin({
                'secret': api_secret_key,
                'type': 'simple',
                'email': email,
            })
            ex.value == ('password', None)

    def test__signin__facebook__invalid_args(
            self, db_engine, auth_logic, api_secret_key,
            email, facebook_id, facebook_token
    ):
        # create record
        db_engine.auth.add_facebook_auth(email, facebook_id, facebook_token)
        # invalid email
        with pytest.raises(sfcd.logic.auth.InvalidArgument) as ex:
            auth_logic.signin({
                'secret': api_secret_key,
                'type': 'facebook',
                'email': 'invalid',
            })
            ex.value == ('email', 'invalid')
        # none facebook
        with pytest.raises(sfcd.logic.auth.InvalidArgument) as ex:
            auth_logic.signin({
                'secret': api_secret_key,
                'type': 'facebook',
                'email': email,
                'facebook_id': '',
                'facebook_token': '',
            })
            ex.value == ('facebook_id', '')
        # no facebook params
        with pytest.raises(sfcd.logic.auth.InvalidArgument) as ex:
            auth_logic.signin({
                'secret': api_secret_key,
                'type': 'facebook',
                'email': email,
                'facebook_id': facebook_id,
            })
            ex.value == ('facebook_token', None)

    def test__signin__simple(
            self, db_engine, auth_logic, api_secret_key,
            email, password
    ):
        # create record
        db_engine.auth.add_simple_auth(email, password)
        #
        assert auth_logic.signin({
            'secret': api_secret_key,
            'type': 'simple',
            'email': email,
            'password': password,
        }) is None

    def test__signin__facebook(
            self, db_engine, auth_logic, api_secret_key,
            email, facebook_id, facebook_token
    ):
        # create record
        db_engine.auth.add_facebook_auth(email, facebook_id, facebook_token)
        #
        assert auth_logic.signin({
            'secret': api_secret_key,
            'type': 'facebook',
            'email': email,
            'facebook_id': facebook_id,
            'facebook_token': facebook_token,
        }) is None

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
        # signin
        assert auth_logic.signin({
            'secret': api_secret_key,
            'type': 'simple',
            'email': email,
            'password': password,
        }) is None

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
        # signin
        assert auth_logic.signin({
            'secret': api_secret_key,
            'type': 'facebook',
            'email': email,
            'facebook_id': facebook_id,
            'facebook_token': facebook_token,
        }) is None
