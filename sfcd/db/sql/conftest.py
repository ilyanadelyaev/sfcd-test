import pytest

import sqlalchemy
import sqlalchemy.orm

import sfcd.db.sql


@pytest.fixture(scope='session')
def _Engine():
    # create engine
    engine = sqlalchemy.create_engine('sqlite:///:memory:', echo=False)
    # create schema
    sfcd.db.sql.create_tables(engine)
    #
    return engine


@pytest.fixture(scope='session')
def _Session(_Engine):
    # init session
    return sqlalchemy.orm.sessionmaker(bind=_Engine)


@pytest.fixture
def session(_Session):
    return _Session()
