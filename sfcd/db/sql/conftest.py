import pytest

import sfcd.db.sql


@pytest.fixture(scope='session')
def session_maker(sql_engine_url):
    # init engine and return session maker
    return sfcd.db.sql.init_engine(engine_url=sql_engine_url)


@pytest.fixture
def session(session_maker):
    return session_maker()
