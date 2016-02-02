import sfcd.logic.exc


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
