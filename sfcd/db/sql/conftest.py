import pytest

import sfcd.db.sql
import sfcd.db.sql.engine


@pytest.fixture(scope='session')
def engine_url():
    return 'sqlite:///:memory:'


@pytest.fixture(scope='session')
def session_maker(engine_url):
    # init engine and return session maker
    return sfcd.db.sql.init_engine(engine_url=engine_url)


@pytest.fixture
def session(session_maker):
    return session_maker()


@pytest.fixture(scope='session')
def db_engine(engine_url):
    return sfcd.db.sql.engine.DBEngine(engine_url)
