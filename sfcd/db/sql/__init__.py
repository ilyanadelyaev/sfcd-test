import sqlalchemy
import sqlalchemy.orm
import sqlalchemy.ext.declarative


# declare base model for all ORM models
BaseModel = sqlalchemy.ext.declarative.declarative_base()


# init engine
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
    return Session


class ManagerBase(object):
    """
    holds session_maker and provide session for db requests
    """

    def __init__(self, session_maker):
        self.session_maker = session_maker

    def get_session(self):
        return self.session_maker()
