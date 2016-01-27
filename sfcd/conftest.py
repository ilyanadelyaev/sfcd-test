import uuid

import pytest

import sfcd.db.sql.engine


########################################
# fixtures
########################################

# auth data

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
def salt():
    return uuid.uuid4().hex


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
def db_engine(sql_engine_url):
    # check pytest args and load --sql or --mongo database
    return sfcd.db.sql.engine.DBEngine(sql_engine_url)
