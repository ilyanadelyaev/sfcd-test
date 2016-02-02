import sfcd.logic.auth.base
import sfcd.logic.auth.exc


class FacebookMethod(sfcd.logic.auth.base.BaseMethod):
    """
    Facebook auth method: email, facebook_id, facebook_token
    """

    @staticmethod
    def validate(facebook_id, facebook_token):
        # not empty
        if not facebook_id:
            raise sfcd.logic.auth.exc.InvalidArgument(
                'facebook_id', facebook_id)
        # not empty
        if not facebook_token:
            raise sfcd.logic.auth.exc.InvalidArgument(
                'facebook_token', facebook_token)

    def signup(self, data):
        email = data.get('email', None)
        facebook_id = data.get('facebook_id', None)
        facebook_token = data.get('facebook_token', None)
        # check params
        self.validate_email(email)
        self.validate(facebook_id, facebook_token)
        # add record to db
        self.db_engine.auth.facebook.register(
            email, facebook_id, facebook_token)

    def signin(self, data):
        email = data.get('email', None)
        facebook_id = data.get('facebook_id', None)
        facebook_token = data.get('facebook_token', None)
        # check params
        self.validate_email(email)
        self.validate(facebook_id, facebook_token)
        # get token or raise exception
        return self.db_engine.auth.facebook.get_auth_token(
            email, facebook_id, facebook_token)
