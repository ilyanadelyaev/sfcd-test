import sfcd.logic.auth.manager


class Controller(object):
    """
    Keep all logic managers here
    Using in requests via flask.g
    """

    def __init__(self, db_engine):
        self.auth = sfcd.logic.auth.manager.Manager(db_engine)
