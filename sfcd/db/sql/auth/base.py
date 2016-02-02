import sqlalchemy

import sfcd.db.sql.base
import sfcd.db.exc
import sfcd.misc.crypto


class Model(sfcd.db.sql.base.BaseModel):
    """
    :id: is system wide auth_id
    :email: must be unique
    """
    __tablename__ = 'auth_base'

    id = sqlalchemy.Column(
        sqlalchemy.Integer,
        primary_key=True,
    )
    email = sqlalchemy.Column(
        sqlalchemy.String(60),
        unique=True,
        index=True,
    )
    auth_token = sqlalchemy.Column(
        sqlalchemy.String(
            sfcd.misc.crypto.Crypto.auth_token_length),
        index=True,  # to process future api reqiests with token
    )


class BaseMethod(object):
    """
    Do not implement!
    """

    # fill empty auth token with zeros
    # to prevent db fragmentation on future insert real auth token
    AUTH_TOKEN_MOCK = \
        '0' * Model.auth_token.property.columns[0].type.length

    def __init__(self, manager):
        self.manager = manager

    @staticmethod
    def _validate_email(email):
        """
        validate email length bounds: (0..max_length]
        raises on error
        """
        if not email:
            raise sfcd.db.exc.AuthError('empty email')
        # way to get max field length
        if len(email) > \
                Model.email.property.columns[0].type.length:
            raise sfcd.db.exc.AuthError('email too long')

    @classmethod
    def _create_id_obj(cls, email):
        """
        Special method for Model record creation
        Fill auth_key with mock to prevent db fragmentation
        """
        return Model(
            email=email,
            auth_token=cls.AUTH_TOKEN_MOCK,
        )

    @classmethod
    def update_auth_token(cls, id_obj):
        """
        DUMMUY
        Check TTL for auth_token
        Update if needed
        return True for update
        """
        # not so fast but now its dummy
        # and will be replaced with ttl stuff on production
        if id_obj.auth_token == cls.AUTH_TOKEN_MOCK:
            id_obj.auth_token = sfcd.misc.crypto.Crypto.generate_auth_token()
            # check here for TTL and so on
            return True
        return False

    def register(self, *args, **kwargs):
        raise NotImplementedError

    def get_auth_token(self, *args, **kwargs):
        raise NotImplementedError
