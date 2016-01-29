import validate_email  # external package

import sfcd.db.exc
import sfcd.logic.common
import sfcd.logic.exc
import sfcd.config


class AuthError(sfcd.logic.exc.LogicError):
    """
    Common logic.auth error
    """
    message_template = 'Unknown auth error with: "{v}"'

    def __init__(self, value):
        super(AuthError, self).__init__(
            self.message_template.format(v=value))


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

    # add auth methods here
    AUTH_METHODS = {
        # auth_type: (signup_func, signin_func)
        'simple': ('_simple_signup', '_simple_signin'),
        'facebook': ('_facebook_signup', '_facebook_signin'),
    }

    def __init__(self, db_engine):
        # process all operations via db engine
        self.db_engine = db_engine

    def _get_auth_func(self, auth_type, func_type):
        """
        ckeck if selected type is allowed in config
        get and check auth func
        :func: 'signup' or 'signin'
        """
        # check for allowed methods in config
        if auth_type not in sfcd.config.AUTH_METHODS:
            raise InvalidAuthType(auth_type)
        # get all funcs
        auth_funcs = self.AUTH_METHODS.get(auth_type, None)
        if not auth_funcs:
            raise InvalidAuthType(auth_type)
        # get and specific func
        if func_type == 'signup':
            func = auth_funcs[0]
        elif func_type == 'signin':
            func = auth_funcs[1]
        else:
            raise InvalidAuthType(auth_type)
        # check func
        if not hasattr(self, func):
            raise InvalidAuthType(auth_type)
        return getattr(self, func)

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
        if not data:
            raise RegistrationError('empty data')

        # check api secret key
        sfcd.logic.common.validate_secret_key(data)

        # validate email
        email = data.get('email', None)
        self._validate_email(email)

        # check if email exists
        if self.db_engine.auth.email_exists(email):
            raise RegistrationError('email "{}" exists'.format(email))

        # call specific function
        auth_type = data.get('type', 'simple')
        try:
            self._get_auth_func(auth_type, 'signup')(data)
        except sfcd.db.exc.AuthError as ex:
            # hide db exception here for human-readable
            raise RegistrationError(ex.message)

    def _simple_signup(self, data):
        email = data.get('email', None)
        password = data.get('password', None)
        # check params
        self._validate_simple(password)
        # add record to db
        self.db_engine.auth.register_simple_auth(email, password)

    def _facebook_signup(self, data):
        email = data.get('email', None)
        facebook_id = data.get('facebook_id', None)
        facebook_token = data.get('facebook_token', None)
        # check params
        self._validate_facebook(facebook_id, facebook_token)
        # add record to db
        self.db_engine.auth.register_facebook_auth(
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
        if not data:
            raise LoginError('empty data')

        # check api secret key
        sfcd.logic.common.validate_secret_key(data)

        # validate email
        email = data.get('email', None)
        self._validate_email(email)

        # call specific function
        auth_type = data.get('type', 'simple')
        try:
            return self._get_auth_func(auth_type, 'signin')(data)
        except sfcd.db.exc.AuthError as ex:
            # hide db exception here for human-readable
            raise LoginError(ex.message)

    def _simple_signin(self, data):
        email = data.get('email', None)
        password = data.get('password', None)
        # check params
        self._validate_simple(password)
        # get token or raise exception
        return self.db_engine.auth.get_token_simple_auth(email, password)

    def _facebook_signin(self, data):
        email = data.get('email', None)
        facebook_id = data.get('facebook_id', None)
        facebook_token = data.get('facebook_token', None)
        # check params
        self._validate_facebook(facebook_id, facebook_token)
        # get token or raise exception
        return self.db_engine.auth.get_token_facebook_auth(
            email, facebook_id, facebook_token)
