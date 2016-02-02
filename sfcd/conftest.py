import uuid

import pytest

import sfcd.misc.config
import sfcd.db.common


########################################
# fixtures
########################################

# auth data

@pytest.fixture(scope='session')
def api_secret_key(config):
    return config.api.secret


@pytest.fixture
def email():
    return '{}@example.com'.format(uuid.uuid4())


@pytest.fixture
def email_2():
    return '{}@example.com'.format(uuid.uuid4())


@pytest.fixture
def password():
    return str(uuid.uuid4())


@pytest.fixture
def auth_token():
    return str(uuid.uuid4())


@pytest.fixture
def facebook_id():
    return str(uuid.uuid4())


@pytest.fixture
def facebook_id_2():
    return str(uuid.uuid4())


@pytest.fixture
def facebook_token():
    return str(uuid.uuid4())


# config

@pytest.fixture(scope='session')
def config(option_db):
    if option_db == 'sql':
        return sfcd.misc.config.Config('./config/test.sql.yaml')
    elif option_db == 'mongo':
        return sfcd.misc.config.Config('./config/test.mongo.yaml')


# db

@pytest.fixture(scope='session')
def db_engine(config):
    return sfcd.db.common.get_db_engine(config)
