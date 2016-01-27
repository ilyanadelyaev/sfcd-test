class Controller(object):
    def __init__(self, db_engine):
        self.db_engine = db_engine

    @property
    def auth(self):
        """
        auth logic lazy
        """
        if not hasattr(self, '_auth') or self._auth is None:
            from . import auth  # avoid circular import
            self._auth = auth.AuthLogic(self.db_engine)
        return self._auth
