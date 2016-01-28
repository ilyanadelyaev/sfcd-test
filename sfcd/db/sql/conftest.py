import pytest

import sfcd.db.sql.engine


@pytest.fixture(scope='session')
def session_maker(sql_engine_url):
    # init engine and return session maker
    _, _session_maker = sfcd.db.sql.engine.DBEngine.init_engine(
        engine_url=sql_engine_url)
    return _session_maker


@pytest.fixture
def session(session_maker):
    return session_maker()
