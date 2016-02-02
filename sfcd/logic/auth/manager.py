import sfcd.logic.common
import sfcd.logic.auth.simple
import sfcd.logic.auth.facebook
import sfcd.logic.auth.exc


class Manager(object):
    """
    make signup and signin here
    verify all parameters here including secret key
    hides all db magic

    using aggregator funcion signup/signin with switch
    and specific functions for auth type
    aggregator functions are extendeble with new auth types
    """

    # add auth processors here
    AUTH_METHODS = {
        # auth_type: auth_processor
        'simple': 'simple',
        'facebook': 'facebook',
    }

    def __init__(self, db_engine):
        self.simple = sfcd.logic.auth.simple.SimpleMethod(db_engine)
        self.facebook = sfcd.logic.auth.facebook.FacebookMethod(db_engine)

    def _auth_processor(self, config, auth_type):
        """
        ckeck if selected type is allowed in config
        get and check auth func
        :func: 'signup' or 'signin'
        """
        # check for allowed methods in config
        if auth_type not in config.api.auth.allowed_methods:
            raise sfcd.logic.auth.exc.InvalidAuthType(auth_type)
        # get auth processor name
        auth_processor_name = self.AUTH_METHODS.get(auth_type, None)
        if not auth_processor_name:
            raise sfcd.logic.auth.exc.InvalidAuthType(auth_type)
        # check processor
        if not hasattr(self, auth_processor_name):
            raise sfcd.logic.auth.exc.InvalidAuthType(auth_type)
        return getattr(self, auth_processor_name)

    def signup(self, config, data):
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
            raise sfcd.logic.auth.exc.RegistrationError('empty data')

        # keep this method on secret side
        # check api secret key
        sfcd.logic.common.validate_secret_key(config, data)

        # call specific function
        auth_type = data.get('type', 'simple')
        try:
            self._auth_processor(config, auth_type).signup(data)
        except sfcd.db.exc.AuthError as ex:
            # hide db exception here for human-readable
            raise sfcd.logic.auth.exc.RegistrationError(ex.message)

    def signin(self, config, data):
        """
        check secret
        check email
        check if email not registered
        call type-specific method
        extendeble with new auth type functions
        raises on error
        """
        if not data:
            raise sfcd.logic.auth.exc.LoginError('empty data')

        # keep this method on secret side
        # check api secret key
        sfcd.logic.common.validate_secret_key(config, data)

        # call specific function
        auth_type = data.get('type', 'simple')
        try:
            return self._auth_processor(config, auth_type).signin(data)
        except sfcd.db.exc.AuthError as ex:
            # hide db exception here for human-readable
            raise sfcd.logic.auth.exc.LoginError(ex.message)
