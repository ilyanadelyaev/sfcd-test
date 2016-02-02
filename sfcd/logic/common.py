import sfcd.logic.exc


def validate_secret_key(secret, data):
    # ? hash(secret)
    data_secret = data.get('secret', None)
    if secret != data_secret:
        raise sfcd.logic.exc.InvalidSecretKey(data_secret)
