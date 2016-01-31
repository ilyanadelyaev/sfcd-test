import contextlib

import sqlalchemy.ext.declarative


# declare base model for all ORM models
BaseModel = sqlalchemy.ext.declarative.declarative_base()


class ManagerBase(object):
    """
    base class for all models managers
    holds session_maker and provide session for db requests
    """

    def __init__(self, session_maker):
        # hide it from all inheritors
        self.__session_maker = session_maker

    @contextlib.contextmanager
    def session_scope(self):
        """
        Using:
        with self.session_scope() as session:
            ...
        """
        session = self.__session_maker()
        try:
            yield session
            session.commit()  # and release all db locks
        except:
            session.rollback()
            raise
        finally:
            session.close()
