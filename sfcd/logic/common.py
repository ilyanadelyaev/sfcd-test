import sfcd.logic.exc
import sfcd.config


def validate_secret_key(data):
    # ? or get if from secret storage
    system_secret = sfcd.config.API_SECRET_KEY
    # ? hash(secret)
    user_secret = data.get('secret', None)
    if system_secret != user_secret:
        raise sfcd.logic.exc.InvalidSecretKey(user_secret)
