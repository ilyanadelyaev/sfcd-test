import sqlalchemy
import sqlalchemy.orm

import sfcd.db.sql.base


class DBEngine(object):
    """
    Hides dababase realisation from logic layer
    Holds db_connection and all managers in one place
    #
    SQL-Alchemy inside
    """

    def __init__(self, engine_url):
        self.engine, self.session_maker = \
            self.init_engine(engine_url=engine_url)

    @staticmethod
    def init_engine(engine_url):
        """
        init procedure for sqlalchemy engine:
        - create engine
        - ensure tables
        - get session maker
        """
        # create engine
        Engine = sqlalchemy.create_engine(engine_url)
        # ensure tables
        sfcd.db.sql.base.BaseModel.metadata.create_all(Engine)
        # get session maker
        Session = sqlalchemy.orm.sessionmaker(bind=Engine)
        return Engine, Session

    @property
    def auth(self):
        """
        auth manager lazy
        create tables for models on lazy way
        """
        # pylint: disable=E0203
        # because magic
        if not hasattr(self, '_auth') or self._auth is None:
            from . import auth  # avoid circular import
            sfcd.db.sql.base.BaseModel.metadata.create_all(self.engine)
            self._auth = auth.AuthManager(self.session_maker)
        return self._auth
