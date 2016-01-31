from . import auth


class Controller(object):
    """
    Keep all logic managers here
    Using in requests via flask.g
    """

    def __init__(self, db_engine):
        self.auth = auth.Manager(db_engine)
