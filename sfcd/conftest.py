import uuid

import pytest

import sfcd.config
import sfcd.db.sql.engine


########################################
# fixtures
########################################

# auth data

@pytest.fixture(scope='session')
def api_secret_key():
    return sfcd.config.API_SECRET_KEY


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


# DB's

@pytest.fixture(scope='session')
def sql_engine_url():
    return 'sqlite:///:memory:'


@pytest.fixture(scope='session')
def mongo_engine_url():
    return 'mongodb://localhost/database_name'


@pytest.fixture(scope='session')
def db_engine(
        sql_engine_url, mongo_engine_url, option_db
):
    if option_db == 'sql':
        return sfcd.db.sql.engine.DBEngine(sql_engine_url)
    elif option_db == 'mongo':
        return None
        # return sfcd.db.mongo.DBEngine(mongo_engine_url)
