import sqlalchemy.ext.declarative


# declare base model for all ORM models
BaseModel = sqlalchemy.ext.declarative.declarative_base()


class ManagerBase(object):
    """
    base class for all models managers
    holds session_maker and provide session for db requests
    """

    def __init__(self, session_maker):
        self.session_maker = session_maker

    def get_session(self):
        return self.session_maker()
