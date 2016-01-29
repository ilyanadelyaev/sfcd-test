import json

import pytest

import flask.ext.webtest

import sfcd.application


@pytest.fixture(scope='session')
def app_objects(
        sql_engine_url, mongo_engine_url, option_db
):
    """
    Kind a hack to initialize web_app and db_engine separately
    """
    db_type = option_db
    db_url = None
    if db_type == 'sql':
        db_url = sql_engine_url
    elif db_type == 'mongo':
        db_url = mongo_engine_url
    flask_app, db_engine = \
        sfcd.application.Application.setup_application(db_type, db_url)
    return flask_app, db_engine


@pytest.fixture(scope='session')
def web_app(app_objects):
    flask_app, _ = app_objects
    return flask.ext.webtest.TestApp(flask_app)


@pytest.fixture(scope='session')
def db_engine(app_objects):
    _, db_engine = app_objects
    return db_engine


class TestAuth:
    def test__signup__get_request(self, web_app):
        resp = web_app.get(
            '/auth/signup/',
            expect_errors=True
        )
        assert resp.status_code == 405

    def test__signup__empty_data(self, web_app):
        resp = web_app.post(
            '/auth/signup/',
            expect_errors=True
        )
        assert resp.status_code == 400
        assert resp.json['error'] == \
            'Registration error with: "empty data"'

    def test__signup__invalid_secret_key(self, web_app):
        resp = web_app.post_json(
            '/auth/signup/',
            {
                'secret': 'secret_key_1',
                'type': 'simple',
            },
            expect_errors=True
        )
        assert resp.status_code == 400
        assert resp.json['error'] == \
            'Invalid secret key: "secret_key_1"'

    def test__signup__invalid_auth_type(
            self, web_app, api_secret_key, email):
        resp = web_app.post_json(
            '/auth/signup/',
            {
                'secret': api_secret_key,
                'type': 'invalid_type_1',
                'email': email,
            },
            expect_errors=True
        )
        assert resp.status_code == 400
        assert resp.json['error'] == \
            'Invalid auth type: "invalid_type_1"'

    def test__signup__invalid_email(
            self, web_app, api_secret_key
    ):
        resp = web_app.post_json(
            '/auth/signup/',
            {
                'secret': api_secret_key,
                'type': 'simple',
                'email': 'invalid_email_1',
            },
            expect_errors=True
        )
        assert resp.status_code == 400
        assert resp.json['error'] == \
            'Ivalid argument email = "invalid_email_1"'

    def test__signup__already_registered(
            self, db_engine, web_app, api_secret_key,
            email, password
    ):
        # add record to db
        db_engine.auth.register_simple_auth(email, password)
        #
        resp = web_app.post_json(
            '/auth/signup/',
            {
                'secret': api_secret_key,
                'type': 'simple',
                'email': email,
                'password': password
            },
            expect_errors=True
        )
        assert resp.status_code == 400
        assert resp.json['error'] == \
            'Registration error with: "email "{}" exists"'.format(email)

    def test__signup__simple(
            self, db_engine, web_app, api_secret_key,
            email, password
    ):
        resp = web_app.post_json(
            '/auth/signup/',
            {
                'secret': api_secret_key,
                'type': 'simple',
                'email': email,
                'password': password,
            },
        )
        assert resp.status_code == 200
        # some token
        assert db_engine.auth.get_token_simple_auth(email, password)

    def test__signup__simple__invalid_password(
            self, web_app, api_secret_key, email
    ):
        resp = web_app.post_json(
            '/auth/signup/',
            {
                'secret': api_secret_key,
                'type': 'simple',
                'email': email,
            },
            expect_errors=True
        )
        assert resp.status_code == 400
        assert resp.json['error'] == \
            'Ivalid argument password = "None"'

    def test__signup__facebook(
            self, db_engine, web_app, api_secret_key,
            email, facebook_id, facebook_token
    ):
        resp = web_app.post_json(
            '/auth/signup/',
            {
                'secret': api_secret_key,
                'type': 'facebook',
                'email': email,
                'facebook_id': facebook_id,
                'facebook_token': facebook_token,
            },
        )
        assert resp.status_code == 200
        # some token
        assert db_engine.auth.get_token_facebook_auth(
            email, facebook_id, facebook_token)

    def test__signup__facebook__facebook_id_exitsts(
            self, db_engine, web_app, api_secret_key,
            email, email_2, facebook_id, facebook_token
    ):
        # add record to db
        db_engine.auth.register_facebook_auth(
            email, facebook_id, facebook_token)
        #
        resp = web_app.post_json(
            '/auth/signup/',
            {
                'secret': api_secret_key,
                'type': 'facebook',
                'email': email_2,
                'facebook_id': facebook_id,
                'facebook_token': facebook_token,
            },
            expect_errors=True
        )
        assert resp.status_code == 400
        assert resp.json['error'] == \
            'Registration error with: "facebook_id "{}" exists"'.format(
                facebook_id)

    def test__signup__facebook__ivalid_facebook_id(
            self, web_app, api_secret_key, email
    ):
        resp = web_app.post_json(
            '/auth/signup/',
            {
                'secret': api_secret_key,
                'type': 'facebook',
                'email': email,
            },
            expect_errors=True
        )
        assert resp.status_code == 400
        assert resp.json['error'] == \
            'Ivalid argument facebook_id = "None"'

    def test__signup__facebook__ivalid_facebook_token(
            self, web_app, api_secret_key, email, facebook_id
    ):
        resp = web_app.post_json(
            '/auth/signup/',
            {
                'secret': api_secret_key,
                'type': 'facebook',
                'email': email,
                'facebook_id': facebook_id,
                'facebook_token': '',
            },
            expect_errors=True
        )
        assert resp.status_code == 400
        assert resp.json['error'] == \
            'Ivalid argument facebook_token = ""'

    def test__signin__get_request(self, web_app):
        resp = web_app.get(
            '/auth/signin/',
            expect_errors=True
        )
        assert resp.status_code == 405

    def test__signin__empty_data(self, web_app):
        resp = web_app.post(
            '/auth/signin/',
            expect_errors=True
        )
        assert resp.status_code == 400
        assert resp.json['error'] == \
            'Login error with: "empty data"'

    def test__signin__invalid_secret_key(self, web_app):
        resp = web_app.post_json(
            '/auth/signin/',
            {
                'secret': 'secret_key_2',
                'type': 'simple',
            },
            expect_errors=True
        )
        assert resp.status_code == 400
        assert resp.json['error'] == \
            'Invalid secret key: "secret_key_2"'

    def test__signin__invalid_auth_type(
            self, web_app, api_secret_key, email):
        resp = web_app.post_json(
            '/auth/signin/',
            {
                'secret': api_secret_key,
                'type': 'invalid_type_2',
                'email': email,
            },
            expect_errors=True
        )
        assert resp.status_code == 400
        assert resp.json['error'] == \
            'Invalid auth type: "invalid_type_2"'

    def test__signin__invalid_email(
            self, web_app, api_secret_key
    ):
        resp = web_app.post_json(
            '/auth/signin/',
            {
                'secret': api_secret_key,
                'type': 'simple',
                'email': 'invalid_email_2',
            },
            expect_errors=True
        )
        assert resp.status_code == 400
        assert resp.json['error'] == \
            'Ivalid argument email = "invalid_email_2"'

    def test__signin__not_registered(
        self, web_app, api_secret_key,
        email, password
    ):
        resp = web_app.post_json(
            '/auth/signin/',
            {
                'secret': api_secret_key,
                'type': 'simple',
                'email': email,
                'password': password,
            },
            expect_errors=True
        )
        assert resp.status_code == 400
        assert resp.json['error'] == \
            'Login error with: "email "{}" not exists"'.format(email)

    def test__signin__simple(
            self, db_engine, web_app, api_secret_key,
            email, password
    ):
        # add record to db
        db_engine.auth.register_simple_auth(
            email, password)
        #
        token_db = db_engine.auth.get_token_simple_auth(
            email, password)
        #
        resp = web_app.post_json(
            '/auth/signin/',
            {
                'secret': api_secret_key,
                'type': 'simple',
                'email': email,
                'password': password,
            },
        )
        assert resp.status_code == 200
        assert resp.json['auth_token'] == token_db

    def test__signin__simple__equal_tokens(
            self, db_engine, web_app, api_secret_key,
            email, password
    ):
        # add record to db
        db_engine.auth.register_simple_auth(
            email, password)
        #
        resp_1 = web_app.post_json(
            '/auth/signin/',
            {
                'secret': api_secret_key,
                'type': 'simple',
                'email': email,
                'password': password,
            },
        )
        resp_2 = web_app.post_json(
            '/auth/signin/',
            {
                'secret': api_secret_key,
                'type': 'simple',
                'email': email,
                'password': password,
            },
        )
        assert resp_1.status_code == 200
        assert resp_2.status_code == 200
        assert resp_2.json['auth_token'] == resp_2.json['auth_token']

    def test__signin__simple__login_error(
            self, db_engine, web_app, api_secret_key,
            email, password
    ):
        # add record to db
        db_engine.auth.register_simple_auth(
            email, password)
        #
        resp = web_app.post_json(
            '/auth/signin/',
            {
                'secret': api_secret_key,
                'type': 'simple',
                'email': email,
                'password': 'invalid_password',
            },
            expect_errors=True
        )
        assert resp.status_code == 400
        assert resp.json['error'] == \
            'Login error with: "invalid password"'

    def test__signin__facebook(
            self, db_engine, web_app, api_secret_key,
            email, facebook_id, facebook_token
    ):
        # add record to db
        db_engine.auth.register_facebook_auth(
            email, facebook_id, facebook_token)
        #
        token_db = db_engine.auth.get_token_facebook_auth(
            email, facebook_id, facebook_token)
        #
        resp = web_app.post_json(
            '/auth/signin/',
            {
                'secret': api_secret_key,
                'type': 'facebook',
                'email': email,
                'facebook_id': facebook_id,
                'facebook_token': facebook_token,
            },
        )
        assert resp.status_code == 200
        assert resp.json['auth_token'] == token_db

    def test__signin__facebook__equal_tokens(
            self, db_engine, web_app, api_secret_key,
            email, facebook_id, facebook_token
    ):
        # add record to db
        db_engine.auth.register_facebook_auth(
            email, facebook_id, facebook_token)
        #
        resp_1 = web_app.post_json(
            '/auth/signin/',
            {
                'secret': api_secret_key,
                'type': 'facebook',
                'email': email,
                'facebook_id': facebook_id,
                'facebook_token': facebook_token,
            },
        )
        resp_2 = web_app.post_json(
            '/auth/signin/',
            {
                'secret': api_secret_key,
                'type': 'facebook',
                'email': email,
                'facebook_id': facebook_id,
                'facebook_token': facebook_token,
            },
        )
        assert resp_1.status_code == 200
        assert resp_2.status_code == 200
        assert resp_2.json['auth_token'] == resp_2.json['auth_token']

    def test__signin__facebook__login_error(
            self, db_engine, web_app, api_secret_key,
            email, facebook_id, facebook_token
    ):
        # add record to db
        db_engine.auth.register_facebook_auth(
            email, facebook_id, facebook_token)
        #
        resp = web_app.post_json(
            '/auth/signin/',
            {
                'secret': api_secret_key,
                'type': 'facebook',
                'email': email,
                'facebook_id': facebook_id,
                'facebook_token': 'invalid_token',
            },
            expect_errors=True
        )
        assert resp.status_code == 400
        assert resp.json['error'] == \
            'Login error with: "invalid passphrase"'
