import pytest

import sfcd.db.sql


@pytest.fixture(scope='session')
def session_maker(sql_engine_url):
    # init engine and return session maker
    _, session_maker = sfcd.db.sql.DBEngine.init_engine(
        engine_url=sql_engine_url)
    return session_maker


@pytest.fixture
def session(session_maker):
    return session_maker()
