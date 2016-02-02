import sfcd.logic.exc


def validate_secret_key(config, data):
    system_secret = config.api.secret
    # ? hash(secret)
    user_secret = data.get('secret', None)
    if system_secret != user_secret:
        raise sfcd.logic.exc.InvalidSecretKey(user_secret)
