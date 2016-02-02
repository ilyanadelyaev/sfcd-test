import sfcd.logic.auth.base
import sfcd.logic.auth.exc


class SimpleMethod(sfcd.logic.auth.base.BaseMethod):
    """
    Simple auth method: email, password
    """

    @staticmethod
    def validate(password):
        # ? check size
        if password is None:
            raise sfcd.logic.auth.exc.InvalidArgument(
                'password', password)

    def signup(self, data):
        email = data.get('email', None)
        password = data.get('password', None)
        # check params
        self.validate_email(email)
        self.validate(password)
        # add record to db
        self.db_engine.auth.simple.register(
            email, password)

    def signin(self, data):
        email = data.get('email', None)
        password = data.get('password', None)
        # check params
        self.validate_email(email)
        self.validate(password)
        # get token or raise exception
        return self.db_engine.auth.simple.get_auth_token(
            email, password)
