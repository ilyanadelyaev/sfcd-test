from . import auth


class Controller(object):
    """
    Keep all logic managers here
    Using in requests via flask.g
    """

    def __init__(self, db_engine):
        self.db_engine = db_engine

    @property
    def auth(self):
        """
        auth logic lazy
        """
        # pylint: disable=E0203
        # because magic
        if not hasattr(self, '_auth') or self._auth is None:
            self._auth = auth.AuthLogic(self.db_engine)
        return self._auth
