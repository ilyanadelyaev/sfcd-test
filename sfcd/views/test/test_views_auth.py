import json

import pytest

import flask.ext.webtest

import sfcd


@pytest.fixture(scope='session')
def web_app(sql_engine_url):
    # TODO: use pytest args here to setup db type
    db_type = 'sql'
    db_url = None
    if db_type == 'sql':
        db_url = sql_engine_url
    elif db_type == 'mongo':
        pass
    sfcd.app = sfcd.Application(db_type, db_url)
    return flask.ext.webtest.TestApp(sfcd.app.web_view)


class TestAuth:
    def test__signup__invalid_secret_key(self, web_app):
        resp = web_app.post_json('/auth/signup/',
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
        resp = web_app.post_json('/auth/signup/',
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
        resp = web_app.post_json('/auth/signup/',
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
            self, web_app, api_secret_key,
            email, password
    ):
        # add record to db
        sfcd.app.db_engine.auth.add_simple_auth(
            email, password)
        #
        resp = web_app.post_json('/auth/signup/',
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
            'Email "{}" already registered'.format(email)

    def test__signup__simple(
            self, web_app, api_secret_key,
            email, password
    ):
        resp = web_app.post_json('/auth/signup/',
            {
                'secret': api_secret_key,
                'type': 'simple',
                'email': email,
                'password': password,
            },
        )
        assert resp.status_code == 200
        # check for auth
        assert sfcd.app.db_engine.auth.check_simple_auth(
            email, password)

    def test__signup__simple__invalid_password(
            self, web_app, api_secret_key, email
    ):
        resp = web_app.post_json('/auth/signup/',
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
            self, web_app, api_secret_key,
            email, facebook_id, facebook_token
    ):
        resp = web_app.post_json('/auth/signup/',
            {
                'secret': api_secret_key,
                'type': 'facebook',
                'email': email,
                'facebook_id': facebook_id,
                'facebook_token': facebook_token,
            },
        )
        assert resp.status_code == 200
        # check for auth
        assert sfcd.app.db_engine.auth.check_facebook_auth(
            email, facebook_id, facebook_token)

    def test__signup__facebook__ivalid_facebook_id(
            self, web_app, api_secret_key, email
    ):
        resp = web_app.post_json('/auth/signup/',
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
        resp = web_app.post_json('/auth/signup/',
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

    def test__signin__invalid_secret_key(self, web_app):
        resp = web_app.post_json('/auth/signin/',
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
        resp = web_app.post_json('/auth/signin/',
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
        resp = web_app.post_json('/auth/signin/',
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
        resp = web_app.post_json('/auth/signin/',
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
            'Login error with: "email "{}" not registred"'.format(email)

    def test__signin__simple(
            self, web_app, api_secret_key,
            email, password
    ):
        # add record to db
        sfcd.app.db_engine.auth.add_simple_auth(
            email, password)
        #
        resp = web_app.post_json('/auth/signin/',
            {
                'secret': api_secret_key,
                'type': 'simple',
                'email': email,
                'password': password,
            },
        )
        assert resp.status_code == 200

    def test__signin__simple__login_error(
            self, web_app, api_secret_key,
            email, password
    ):
        # add record to db
        sfcd.app.db_engine.auth.add_simple_auth(
            email, password)
        #
        resp = web_app.post_json('/auth/signin/',
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
            self, web_app, api_secret_key,
            email, facebook_id, facebook_token
    ):
        # add record to db
        sfcd.app.db_engine.auth.add_facebook_auth(
            email, facebook_id, facebook_token)
        #
        resp = web_app.post_json('/auth/signin/',
            {
                'secret': api_secret_key,
                'type': 'facebook',
                'email': email,
                'facebook_id': facebook_id,
                'facebook_token': facebook_token,
            },
        )
        assert resp.status_code == 200

    def test__signin__facebook__login_error(
            self, web_app, api_secret_key,
            email, facebook_id, facebook_token
    ):
        # add record to db
        sfcd.app.db_engine.auth.add_facebook_auth(
            email, facebook_id, facebook_token)
        #
        resp = web_app.post_json('/auth/signin/',
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
            'Login error with: "invalid login data"'