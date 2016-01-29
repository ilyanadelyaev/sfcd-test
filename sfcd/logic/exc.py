class LogicError(Exception):
    """
    Common logic error
    """


class InvalidSecretKey(LogicError):
    """
    Secret key invalid or not specified
    """
    def __init__(self, value):
        super(InvalidSecretKey, self).__init__(
            'Invalid secret key: "{}"'.format(value))
