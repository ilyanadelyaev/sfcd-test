import pytest

import sfcd.db.sql.engine
import sfcd.db.sql.base


@pytest.fixture(scope='session')
def session_maker(sql_engine_url):
    """
    init engine and return session maker
    """
    _, _session_maker = sfcd.db.sql.engine.DBEngine.init_engine(
        engine_url=sql_engine_url)
    return _session_maker


@pytest.fixture(scope='session')
def __manager_base(session_maker):
    """
    middleware for session_scope fixture
    """
    return sfcd.db.sql.base.ManagerBase(session_maker)


@pytest.fixture
def session_scope(__manager_base):
    """
    correctly close sessions
    """
    return __manager_base.session_scope
