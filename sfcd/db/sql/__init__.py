import sqlalchemy
import sqlalchemy.orm
import sqlalchemy.ext.declarative


# declare base model for all ORM models
BaseModel = sqlalchemy.ext.declarative.declarative_base()


class DBEngine(object):
    """
    Hides dababase realisation from logic layer
    Holds db_connection and all managers in one place
    #
    SQL-Alchemy inside
    """

    def __init__(self, engine_url):
        self.engine, self.session_maker = self.init_engine(engine_url=engine_url)

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
        BaseModel.metadata.create_all(Engine)
        # get session maker
        Session = sqlalchemy.orm.sessionmaker(bind=Engine)
        return Engine, Session

    @property
    def auth(self):
        """
        auth manager lazy
        """
        if not hasattr(self, '_auth') or self._auth is None:
            from . import auth  # avoid circular import
            BaseModel.metadata.create_all(self.engine)
            self._auth = auth.AuthManager(self.session_maker)
        return self._auth


class ManagerBase(object):
    """
    holds session_maker and provide session for db requests
    """

    def __init__(self, session_maker):
        self.session_maker = session_maker

    def get_session(self):
        return self.session_maker()
