import pytest

import sfcd.db.exc
import sfcd.logic.auth
import sfcd.logic.exc


@pytest.fixture(scope='session')
def manager(db_engine):
    return sfcd.logic.auth.Manager(db_engine)


class TestManager:
    def test__interface(self, manager):
        """
        have interface methods
        """
        assert hasattr(manager, 'signup')
        assert hasattr(manager, 'signin')

    def test__processors(self, manager):
        """
        have properties for processors
        """
        assert isinstance(
            manager.simple,
            sfcd.logic.auth.Manager.SimpleMethod
        )
        #
        assert isinstance(
            manager.facebook,
            sfcd.logic.auth.Manager.FacebookMethod
        )

    def test__auth_processor(self, manager):
        """
        _auth_processor returns processor or raise
        """
        processor = manager._auth_processor('simple')
        assert isinstance(
            processor,
            sfcd.logic.auth.Manager.SimpleMethod
        )
        #
        processor = manager._auth_processor('facebook')
        assert isinstance(
            processor,
            sfcd.logic.auth.Manager.FacebookMethod
        )
        #
        with pytest.raises(sfcd.logic.auth.InvalidAuthType) as ex_info:
            manager._auth_processor('invalid')
        assert ex_info.value.message == \
            'Invalid auth type: "invalid"'

    def test__signup__invalid_secret(self, manager):
        """
        invalid secret key
        """
        with pytest.raises(sfcd.logic.exc.InvalidSecretKey) as ex_info:
            manager.signup({
                'secret': 'invalid',
            })
        assert ex_info.value.message == \
            'Invalid secret key: "invalid"'

    def test__signup__invalid_input_data(self, manager):
        """
        check for empty input
        """
        with pytest.raises(sfcd.logic.auth.RegistrationError) as ex_info:
            manager.signup(None)
        assert ex_info.value.message == \
            'Registration error with: "empty data"'
        #
        with pytest.raises(sfcd.logic.auth.RegistrationError) as ex_info:
            manager.signup({})
        assert ex_info.value.message == \
            'Registration error with: "empty data"'

    def test__signup__ivalid_auth_type(self, manager, api_secret_key):
        """
        invalid auth method
        """
        with pytest.raises(sfcd.logic.auth.InvalidAuthType) as ex_info:
            manager.signup({
                'secret': api_secret_key,
                'type': 'invalid',
            })
        assert ex_info.value.message == \
            'Invalid auth type: "invalid"'

    def test__signup__raises_registration_error(
            self, db_engine, manager, api_secret_key,
            email, password
    ):
        """
        cover processor exception with RegistrationError
        """
        db_engine.auth.register_simple_auth(email, password)
        #
        with pytest.raises(sfcd.logic.auth.RegistrationError) as ex_info:
            manager.signup({
                'secret': api_secret_key,
                'type': 'simple',
                'email': email,
                'password': password,
            })
        assert ex_info.value.message == \
            'Registration error with: "email "{}" exists"'.format(email)

    def test__signin__invalid_secret(self, manager):
        """
        invalid secret key
        """
        with pytest.raises(sfcd.logic.exc.InvalidSecretKey) as ex_info:
            manager.signin({
                'secret': 'invalid',
            })
        assert ex_info.value.message == \
            'Invalid secret key: "invalid"'

    def test__signin__invalid_input_data(self, manager):
        """
        check for empty input
        """
        with pytest.raises(sfcd.logic.auth.LoginError) as ex_info:
            manager.signin(None)
        assert ex_info.value.message == \
            'Login error with: "empty data"'
        #
        with pytest.raises(sfcd.logic.auth.LoginError) as ex_info:
            manager.signin({})
        assert ex_info.value.message == \
            'Login error with: "empty data"'

    def test__signin__ivalid_auth_type(self, manager, api_secret_key):
        """
        invalid auth method
        """
        with pytest.raises(sfcd.logic.auth.InvalidAuthType) as ex_info:
            manager.signin({
                'secret': api_secret_key,
                'type': 'invalid',
            })
        assert ex_info.value.message == \
            'Invalid auth type: "invalid"'

    def test__signin__raises_login_error(
            self, manager, api_secret_key,
            email, facebook_id, facebook_token
    ):
        """
        cover processor exception with LoginError
        """
        with pytest.raises(sfcd.logic.auth.LoginError) as ex_info:
            manager.signin({
                'secret': api_secret_key,
                'type': 'facebook',
                'email': email,
                'facebook_id': facebook_id,
                'facebook_token': facebook_token,
            })
        assert ex_info.value.message == \
            'Login error with: "email "{}" not exists"'.format(email)


class TestBaseMethod:
    def test__validate_email(self, manager, email, email_2):
        assert manager.BaseMethod.validate_email(email) is None
        assert manager.BaseMethod.validate_email(email_2) is None
        assert manager.BaseMethod.validate_email(
            'me@example.com') is None
        assert manager.BaseMethod.validate_email(
            'me.and.you@example.com') is None
        #
        with pytest.raises(sfcd.logic.auth.InvalidArgument) as ex_info:
            manager.BaseMethod.validate_email('example')
        assert ex_info.value.message == \
            'Ivalid argument {} = "{}"'.format('email', 'example')
        with pytest.raises(sfcd.logic.auth.InvalidArgument) as ex_info:
            manager.BaseMethod.validate_email('example.com')
        assert ex_info.value.message == \
            'Ivalid argument {} = "{}"'.format('email', 'example.com')
        with pytest.raises(sfcd.logic.auth.InvalidArgument) as ex_info:
            manager.BaseMethod.validate_email('@example.com')
        assert ex_info.value.message == \
            'Ivalid argument {} = "{}"'.format('email', '@example.com')
        with pytest.raises(sfcd.logic.auth.InvalidArgument) as ex_info:
            manager.BaseMethod.validate_email('.@example.com')
        assert ex_info.value.message == \
            'Ivalid argument {} = "{}"'.format('email', '.@example.com')

    def test__validate(self, manager):
        with pytest.raises(NotImplementedError):
            manager.BaseMethod(None).validate()

    def test__signup(self, manager):
        with pytest.raises(NotImplementedError):
            manager.BaseMethod(None).signup()

    def test__signin(self, manager):
        with pytest.raises(NotImplementedError):
            manager.BaseMethod(None).signin()


class TestSimpleMethod:
    def test__validate(
            self, manager,
            password
    ):
        assert manager.simple.validate(password) is None
        #
        with pytest.raises(sfcd.logic.auth.InvalidArgument) as ex_info:
            manager.simple.validate(None)
        assert ex_info.value.message == \
            'Ivalid argument {} = "{}"'.format('password', None)

    def test__signup__invalid_args(
            self, manager,
            email, password
    ):
        # invalid email
        with pytest.raises(sfcd.logic.auth.InvalidArgument) as ex_info:
            manager.simple.signup({
                'email': 'invalid',
                'password': password,
            })
        assert ex_info.value.message == \
            'Ivalid argument {} = "{}"'.format('email', 'invalid')
        # invalid password
        with pytest.raises(sfcd.logic.auth.InvalidArgument) as ex_info:
            manager.simple.signup({
                'email': email,
                'password': None,
            })
        assert ex_info.value.message == \
            'Ivalid argument {} = "{}"'.format('password', None)

    def test__signup__email_exists(
            self, db_engine, manager,
            email, password
    ):
        db_engine.auth.register_simple_auth(email, password)
        #
        with pytest.raises(sfcd.db.exc.AuthError) as ex_info:
            manager.simple.signup({
                'email': email,
                'password': password,
            })
        assert ex_info.value.message == \
            'email "{}" exists'.format(email)

    def test__signup(
            self, db_engine, manager,
            email, password
    ):
        manager.simple.signup({
            'email': email,
            'password': password,
        })
        # exists
        assert db_engine.auth.get_token_simple_auth(
            email, password)

    def test__signin__invalid_args(
            self, manager,
            email, password
    ):
        # invalid email
        with pytest.raises(sfcd.logic.auth.InvalidArgument) as ex_info:
            manager.simple.signin({
                'email': 'invalid',
            })
        assert ex_info.value.message == \
            'Ivalid argument {} = "{}"'.format('email', 'invalid')
        # none password
        with pytest.raises(sfcd.logic.auth.InvalidArgument) as ex_info:
            manager.simple.signin({
                'email': email,
                'password': None
            })
        assert ex_info.value.message == \
            'Ivalid argument {} = "{}"'.format('password', None)
        # no password
        with pytest.raises(sfcd.logic.auth.InvalidArgument) as ex_info:
            manager.simple.signin({
                'email': email,
            })
        assert ex_info.value.message == \
            'Ivalid argument {} = "{}"'.format('password', None)

    def test__signin__email_not_exists(
            self, manager,
            email, password
    ):
        with pytest.raises(sfcd.db.exc.AuthError) as ex_info:
            manager.simple.signin({
                'email': email,
                'password': password,
            })
        assert ex_info.value.message == \
            'email "{}" not exists'.format(email)

    def test__signin__invalid_password(
            self, db_engine, manager,
            email, password
    ):
        # create record
        db_engine.auth.register_simple_auth(email, password)
        #
        with pytest.raises(sfcd.db.exc.AuthError) as ex_info:
            manager.simple.signin({
                'email': email,
                'password': 'invalid',
            })
        assert ex_info.value.message == \
            'invalid password'

    def test__signin(
            self, db_engine, manager,
            email, password
    ):
        # create record
        db_engine.auth.register_simple_auth(email, password)
        #
        token = manager.simple.signin({
            'email': email,
            'password': password,
        })
        #
        token_db = db_engine.auth.get_token_simple_auth(
            email, password)
        #
        assert len(token) == sfcd.misc.Crypto.auth_token_length
        assert token == token_db

    def test__signin__equal_tokens(
            self, db_engine, manager,
            email, password
    ):
        # create record
        db_engine.auth.register_simple_auth(email, password)
        #
        token_1 = manager.simple.signin({
            'email': email,
            'password': password,
        })
        token_2 = manager.simple.signin({
            'email': email,
            'password': password,
        })
        assert len(token_1) == sfcd.misc.Crypto.auth_token_length
        assert token_1 == token_2

    def test__signup_signin(
            self, manager,
            email, password
    ):
        # signup
        assert manager.simple.signup({
            'email': email,
            'password': password,
        }) is None
        # signin - some token
        assert manager.simple.signin({
            'email': email,
            'password': password,
        })


class TestFacebookMethod:
    def test__validate(
            self, manager,
            facebook_id, facebook_token
    ):
        assert manager.facebook.validate(
            facebook_id, facebook_token
        ) is None
        #
        with pytest.raises(sfcd.logic.auth.InvalidArgument) as ex_info:
            manager.facebook.validate('', facebook_token)
        assert ex_info.value.message == \
            'Ivalid argument {} = "{}"'.format('facebook_id', '')
        with pytest.raises(sfcd.logic.auth.InvalidArgument) as ex_info:
            manager.facebook.validate(facebook_id, None)
        assert ex_info.value.message == \
            'Ivalid argument {} = "{}"'.format('facebook_token', None)

    def test__signup__invalid_args(
            self, manager,
            email, facebook_id, facebook_token
    ):
        # invalid email
        with pytest.raises(sfcd.logic.auth.InvalidArgument) as ex_info:
            manager.facebook.signup({
                'email': 'invalid',
                'facebook_id': facebook_id,
                'facebook_token': facebook_token,
            })
        assert ex_info.value.message == \
            'Ivalid argument {} = "{}"'.format('email', 'invalid')
        # invalid facebook_id
        with pytest.raises(sfcd.logic.auth.InvalidArgument) as ex_info:
            manager.facebook.signup({
                'email': email,
                'facebook_id': '',
                'facebook_token': facebook_token,
            })
        assert ex_info.value.message == \
            'Ivalid argument {} = "{}"'.format('facebook_id', '')
        # invalid facebook_token
        with pytest.raises(sfcd.logic.auth.InvalidArgument) as ex_info:
            manager.facebook.signup({
                'email': email,
                'facebook_id': facebook_id,
                'facebook_token': None,
            })
        assert ex_info.value.message == \
            'Ivalid argument {} = "{}"'.format('facebook_token', None)
        # no facebook args
        with pytest.raises(sfcd.logic.auth.InvalidArgument) as ex_info:
            manager.facebook.signup({
                'email': email,
            })
        assert ex_info.value.message == \
            'Ivalid argument {} = "{}"'.format('facebook_id', None)

    def test__signup__email_exists(
            self, db_engine, manager,
            email, facebook_id, facebook_token
    ):
        db_engine.auth.register_facebook_auth(
            email, facebook_id, facebook_token)
        #
        with pytest.raises(sfcd.db.exc.AuthError) as ex_info:
            manager.facebook.signup({
                'email': email,
                'facebook_id': facebook_id,
                'facebook_token': facebook_token,
            })
        assert ex_info.value.message == \
            'email "{}" exists'.format(email)

    def test__signup__facebook_id_exitsts(
            self, manager,
            email, email_2, facebook_id, facebook_token
    ):
        manager.facebook.signup({
            'email': email,
            'facebook_id': facebook_id,
            'facebook_token': facebook_token,
        })
        #
        with pytest.raises(sfcd.db.exc.AuthError) as ex_info:
            manager.facebook.signup({
                'email': email_2,
                'facebook_id': facebook_id,
                'facebook_token': facebook_token,
            })
        assert ex_info.value.message == \
            'facebook_id "{}" exists'.format(facebook_id)

    def test__signup(
            self, db_engine, manager,
            email, facebook_id, facebook_token
    ):
        manager.facebook.signup({
            'email': email,
            'facebook_id': facebook_id,
            'facebook_token': facebook_token,
        })
        # exists
        assert db_engine.auth.get_token_facebook_auth(
            email, facebook_id, facebook_token)

    def test__signin__invalid_args(
            self, manager,
            email, facebook_id, facebook_token
    ):
        # invalid email
        with pytest.raises(sfcd.logic.auth.InvalidArgument) as ex_info:
            manager.facebook.signin({
                'email': 'invalid',
            })
        assert ex_info.value.message == \
            'Ivalid argument {} = "{}"'.format('email', 'invalid')
        # none facebook
        with pytest.raises(sfcd.logic.auth.InvalidArgument) as ex_info:
            manager.facebook.signin({
                'email': email,
                'facebook_id': '',
                'facebook_token': '',
            })
        assert ex_info.value.message == \
            'Ivalid argument {} = "{}"'.format('facebook_id', '')
        # no facebook params
        with pytest.raises(sfcd.logic.auth.InvalidArgument) as ex_info:
            manager.facebook.signin({
                'email': email,
                'facebook_id': facebook_id,
            })
        assert ex_info.value.message == \
            'Ivalid argument {} = "{}"'.format('facebook_token', None)

    def test__signin__email_not_exists(
            self, manager,
            email, facebook_id, facebook_token
    ):
        with pytest.raises(sfcd.db.exc.AuthError) as ex_info:
            manager.facebook.signin({
                'email': email,
                'facebook_id': facebook_id,
                'facebook_token': facebook_token,
            })
        assert ex_info.value.message == \
            'email "{}" not exists'.format(email)

    def test__signin__facebook_id_not_exists(
            self, db_engine, manager,
            email, facebook_id, facebook_token
    ):
        # create record
        db_engine.auth.register_facebook_auth(
            email, facebook_id, facebook_token)
        #
        with pytest.raises(sfcd.db.exc.AuthError) as ex_info:
            manager.facebook.signin({
                'email': email,
                'facebook_id': 'invalid',
                'facebook_token': facebook_token,
            })
        assert ex_info.value.message == \
            'facebook_id "invalid" not exists'

    def test__signin__invalid_passphrase(
            self, db_engine, manager,
            email, facebook_id, facebook_token
    ):
        # create record
        db_engine.auth.register_facebook_auth(
            email, facebook_id, facebook_token)
        #
        with pytest.raises(sfcd.db.exc.AuthError) as ex_info:
            manager.facebook.signin({
                'email': email,
                'facebook_id': facebook_id,
                'facebook_token': 'invalid',
            })
        assert ex_info.value.message == \
            'invalid passphrase'

    def test__signin(
            self, db_engine, manager,
            email, facebook_id, facebook_token
    ):
        # create record
        db_engine.auth.register_facebook_auth(
            email, facebook_id, facebook_token)
        #
        token = manager.facebook.signin({
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

    def test__signin__equal_tokens(
            self, db_engine, manager,
            email, facebook_id, facebook_token
    ):
        # create record
        db_engine.auth.register_facebook_auth(
            email, facebook_id, facebook_token)
        #
        token_1 = manager.facebook.signin({
            'email': email,
            'facebook_id': facebook_id,
            'facebook_token': facebook_token,
        })
        token_2 = manager.facebook.signin({
            'email': email,
            'facebook_id': facebook_id,
            'facebook_token': facebook_token,
        })
        assert len(token_1) == sfcd.misc.Crypto.auth_token_length
        assert token_1 == token_2

    def test__signup_signin(
        self, db_engine, manager,
        email, facebook_id, facebook_token
    ):
        # signup
        assert manager.facebook.signup({
            'email': email,
            'facebook_id': facebook_id,
            'facebook_token': facebook_token,
        }) is None
        # signin - some token
        assert manager.facebook.signin({
            'email': email,
            'facebook_id': facebook_id,
            'facebook_token': facebook_token,
        })
