import validate_email  # external package

import sfcd.logic.auth.exc


class BaseMethod(object):
    """
    Inherit specific auth method processors from here
    """

    def __init__(self, db_engine):
        self.db_engine = db_engine

    @staticmethod
    def validate_email(email):
        if email is None:
            raise sfcd.logic.auth.exc.InvalidArgument('email', email)
        # validate via extended package "validate-email"
        if not validate_email.validate_email(email):
            raise sfcd.logic.auth.exc.InvalidArgument('email', email)

    @staticmethod
    def validate(*args, **kwargs):
        raise NotImplementedError

    def signup(self, *args, **kwargs):
        raise NotImplementedError

    def signin(self, *args, **kwargs):
        raise NotImplementedError
