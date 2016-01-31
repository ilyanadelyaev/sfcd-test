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


class Manager(object):
    """
    make signup and signin here
    verify all parameters here including secret key
    hides all db magic

    using aggregator funcion signup/signin with switch
    and specific functions for auth type
    aggregator functions are extendeble with new auth types
    """

    class BaseMethod(object):
        """
        Inherit specific auth method processors from here
        """
        def __init__(self, db_engine):
            self.db_engine = db_engine

        @staticmethod
        def validate_email(email):
            if email is None:
                raise InvalidArgument('email', email)
            # validate via extended package "validate-email"
            if not validate_email.validate_email(email):
                raise InvalidArgument('email', email)

        @staticmethod
        def validate(*args, **kwargs):
            raise NotImplementedError

        def signup(self, *args, **kwargs):
            raise NotImplementedError

        def signin(self, *args, **kwargs):
            raise NotImplementedError

    class SimpleMethod(BaseMethod):
        @staticmethod
        def validate(password):
            # ? check size
            if password is None:
                raise InvalidArgument('password', password)

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

    class FacebookMethod(BaseMethod):
        @staticmethod
        def validate(facebook_id, facebook_token):
            # not empty
            if not facebook_id:
                raise InvalidArgument('facebook_id', facebook_id)
            # not empty
            if not facebook_token:
                raise InvalidArgument('facebook_token', facebook_token)

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

    # add auth processors here
    AUTH_METHODS = {
        # auth_type: auth_processor
        'simple': 'simple',
        'facebook': 'facebook',
    }

    def __init__(self, db_engine):
        self.simple = self.SimpleMethod(db_engine)
        self.facebook = self.FacebookMethod(db_engine)

    def _auth_processor(self, auth_type):
        """
        ckeck if selected type is allowed in config
        get and check auth func
        :func: 'signup' or 'signin'
        """
        # check for allowed methods in config
        if auth_type not in sfcd.config.AUTH_METHODS:
            raise InvalidAuthType(auth_type)
        # get auth processor name
        auth_processor_name = self.AUTH_METHODS.get(auth_type, None)
        if not auth_processor_name:
            raise InvalidAuthType(auth_type)
        # check processor
        if not hasattr(self, auth_processor_name):
            raise InvalidAuthType(auth_type)
        return getattr(self, auth_processor_name)

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

        # keep this method on secret side
        # check api secret key
        sfcd.logic.common.validate_secret_key(data)

        # call specific function
        auth_type = data.get('type', 'simple')
        try:
            self._auth_processor(auth_type).signup(data)
        except sfcd.db.exc.AuthError as ex:
            # hide db exception here for human-readable
            raise RegistrationError(ex.message)

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

        # keep this method on secret side
        # check api secret key
        sfcd.logic.common.validate_secret_key(data)

        # call specific function
        auth_type = data.get('type', 'simple')
        try:
            return self._auth_processor(auth_type).signin(data)
        except sfcd.db.exc.AuthError as ex:
            # hide db exception here for human-readable
            raise LoginError(ex.message)
