import validate_email  # external package

import sfcd.config


class AuthError(Exception):
    """
    Common auth error
    """
    def __init__(self, value, *args):
        self.value = value
        self.args = args

class InvalidSecretKey(AuthError):
    """
    Secret key invalid or not specified
    value = secret_key
    """

class InvalidAuthType(AuthError):
    """
    auth type not supported
    value = auth_type
    """

class InvalidArgument(AuthError):
    """
    auth argument not valid
    value = (arg_name, arg_value)
    """

class AlreadyRegistered(AuthError):
    """
    Cannot signup
    Specified email already registered
    value = email
    """

class LoginError(AuthError):
    """
    Error via logging procedure
    value = error_text_tepmplate
    args = teplate_params
    """


class AuthLogic(object):
    """
    make signup and signin here
    verify all parameters here including secret key
    hides all db magic

    using aggregator funcion signup/signin with switch
    and specific functions for auth type
    aggregator functions are extendeble with new auth types
    """

    def __init__(self, db_engine):
        # process all operations via db engine
        self.db_engine = db_engine
        # ? or get if from secret storage
        self.secret = sfcd.config.API_SECRET_KEY

    def _check_secret(self, data):
        # ? hash(secret)
        secret = data.get('secret', None)
        if not secret == sfcd.config.API_SECRET_KEY:
            raise InvalidSecretKey(secret)

    @staticmethod
    def _validate_email(email):
        # validate via extended package "validate-email"
        if not validate_email.validate_email(email):
            raise InvalidArgument(('email', email))

    @staticmethod
    def _validate_simple(password):
        # ? check size
        if password is None:
            raise InvalidArgument(('password', password))

    @staticmethod
    def _validate_facebook(facebook_id, facebook_token):
        # not empty
        if not facebook_id:
            raise InvalidArgument(('facebook_id', facebook_id))
        # not empty
        if not facebook_token:
            raise InvalidArgument(('facebook_token', facebook_token))

    def signup(self, data):
        """
        check secret
        check auth type
        validate email
        check if email already registered
        call type-specific method
        extendeble with new specific methods
        raises on error
        """
        # check api secret key
        self._check_secret(data)

        # validate email
        email = data.get('email', None)
        self._validate_email(email)

        # check if auth record exists
        if self.db_engine.auth.auth_exists(email):
            raise AlreadyRegistered(email)

        auth_type = data.get('type', 'simple')

        # check for allowed methods in config
        if auth_type not in sfcd.config.AUTH_METHODS:
            auth_type = None

        if auth_type == 'simple':
            self._simple_signup(data)
        elif auth_type == 'facebook':
            self._facebook_signup(data)

        # add more auth methods here

        else:
            raise InvalidAuthType(auth_type)

    def _simple_signup(self, data):
        email = data.get('email', None)
        password = data.get('password', None)
        # check params
        self._validate_simple(password)
        # add record to db
        self.db_engine.auth.add_simple_auth(email, password)

    def _facebook_signup(self, data):
        email = data.get('email', None)
        facebook_id = data.get('facebook_id', None)
        facebook_token = data.get('facebook_token', None)
        # check params
        self._validate_facebook(facebook_id, facebook_token)
        # add record to db
        self.db_engine.auth.add_facebook_auth(email, facebook_id, facebook_token)

    def signin(self, data):
        """
        check secret
        check email
        check if email not registered
        call type-specific method
        extendeble with new auth type functions
        raises on error
        """
        # check api secret key
        self._check_secret(data)

        # validate email
        # ? because we can
        email = data.get('email', None)
        self._validate_email(email)

        # check if auth record exists
        if not self.db_engine.auth.auth_exists(email):
            raise LoginError('Email "%s" not registred', email)

        auth_type = data.get('type', 'simple')

        # check for allowed methods in config
        if auth_type not in sfcd.config.AUTH_METHODS:
            auth_type = None

        if auth_type == 'simple':
            self._simple_signin(data)
        elif auth_type == 'facebook':
            self._facebook_signin(data)

        # add more auth methods here

        else:
            raise InvalidAuthType(auth_type)

    def _simple_signin(self, data):
        email = data.get('email', None)
        password = data.get('password', None)
        # check params
        self._validate_simple(password)
        #
        if not self.db_engine.auth.check_simple_auth(
                email, password):
            raise LoginError('Invalid password')

    def _facebook_signin(self, data):
        email = data.get('email', None)
        facebook_id = data.get('facebook_id', None)
        facebook_token = data.get('facebook_token', None)
        # check params
        self._validate_facebook(facebook_id, facebook_token)
        #
        if not self.db_engine.auth.check_facebook_auth(
                email, facebook_id, facebook_token):
            raise LoginError('Invalid facebook_id or facebook_token')
