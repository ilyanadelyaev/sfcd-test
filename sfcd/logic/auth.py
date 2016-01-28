import validate_email  # external package

import sfcd.db.exc
import sfcd.config


class AuthError(Exception):
    """
    Common auth error
    """
    message_template = 'Unknown auth error with: "{v}"'

    def __init__(self, value):
        super(AuthError, self).__init__(
            self.message_template.format(v=value))


class InvalidSecretKey(AuthError):
    """
    Secret key invalid or not specified
    """
    message_template = 'Invalid secret key: "{v}"'


class InvalidAuthType(AuthError):
    """
    auth type not supported
    """
    message_template = 'Invalid auth type: "{v}"'


class InvalidArgument(AuthError):
    """
    auth argument not valid
    """
    message_template = 'Ivalid argument {v[0]} = "{v[1]}"'

    def __init__(self, tp, vl):
        super(InvalidArgument, self).__init__((tp, vl))


class RegistrationError(AuthError):
    """
    Registration error
    :value: = error text
    """
    message_template = 'Registration error with: "{v}"'


class LoginError(AuthError):
    """
    Login error
    :value: = error text
    """
    message_template = 'Login error with: "{v}"'


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
        if not secret == self.secret:
            raise InvalidSecretKey(secret)

    @staticmethod
    def _validate_email(email):
        if email is None:
            raise InvalidArgument('email', email)
        # validate via extended package "validate-email"
        if not validate_email.validate_email(email):
            raise InvalidArgument('email', email)

    @staticmethod
    def _validate_simple(password):
        # ? check size
        if password is None:
            raise InvalidArgument('password', password)

    @staticmethod
    def _validate_facebook(facebook_id, facebook_token):
        # not empty
        if not facebook_id:
            raise InvalidArgument('facebook_id', facebook_id)
        # not empty
        if not facebook_token:
            raise InvalidArgument('facebook_token', facebook_token)

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

        auth_type = data.get('type', 'simple')

        # check for allowed methods in config
        if auth_type not in sfcd.config.AUTH_METHODS:
            raise InvalidAuthType(auth_type)

        # check if email exists
        if self.db_engine.auth.email_exists(email):
            raise RegistrationError('email "{}" exists'.format(email))

        try:
            if auth_type == 'simple':
                self._simple_signup(data)
            elif auth_type == 'facebook':
                self._facebook_signup(data)

            # add more auth methods here

        except sfcd.db.exc.AuthError as ex:
            raise RegistrationError(ex.message)

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
        self.db_engine.auth.add_facebook_auth(
            email, facebook_id, facebook_token)

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

        auth_type = data.get('type', 'simple')

        # check for allowed methods in config
        if auth_type not in sfcd.config.AUTH_METHODS:
            raise InvalidAuthType(auth_type)

        try:
            if auth_type == 'simple':
                self._simple_signin(data)
            elif auth_type == 'facebook':
                self._facebook_signin(data)

            # add more auth methods here

        except sfcd.db.exc.AuthError as ex:
            raise LoginError(ex.message)

    def _simple_signin(self, data):
        email = data.get('email', None)
        password = data.get('password', None)
        # check params
        self._validate_simple(password)
        # check db
        self.db_engine.auth.check_simple_auth(email, password)

    def _facebook_signin(self, data):
        email = data.get('email', None)
        facebook_id = data.get('facebook_id', None)
        facebook_token = data.get('facebook_token', None)
        # check params
        self._validate_facebook(facebook_id, facebook_token)
        # check db
        self.db_engine.auth.check_facebook_auth(
            email, facebook_id, facebook_token)
