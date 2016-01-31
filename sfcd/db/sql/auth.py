import logging

import sqlalchemy
import sqlalchemy.types
import sqlalchemy.sql
import sqlalchemy.sql.expression
import sqlalchemy.exc

import sfcd.misc
import sfcd.db.exc
import sfcd.db.sql.base


logger = logging.getLogger('sfcd')


########################################
# Models
########################################

class ID(sfcd.db.sql.base.BaseModel):
    """
    :id: is system wide auth_id
    :email: must be unique
    """
    __tablename__ = 'auth_id'

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
        sqlalchemy.types.String(
            sfcd.misc.Crypto.auth_token_length),
    )


class Simple(sfcd.db.sql.base.BaseModel):
    """
    :hashed: and :salt: to securely store user password
    """
    __tablename__ = 'auth_simple'

    auth_id = sqlalchemy.Column(
        sqlalchemy.Integer,
        sqlalchemy.ForeignKey('auth_id.id'),
        primary_key=True,  # kind a sql-alchemy problem: model must have pk
    )
    hashed = sqlalchemy.Column(
        sqlalchemy.String(sfcd.misc.Crypto.hashed_length)
    )
    salt = sqlalchemy.Column(
        sqlalchemy.String(sfcd.misc.Crypto.salt_length)
    )


class Facebook(sfcd.db.sql.base.BaseModel):
    """
    :facebook_id: unique facebook user identifier
    :hashed: and :salt: to securely store facebook_token
    """
    __tablename__ = 'auth_facebook'

    auth_id = sqlalchemy.Column(
        sqlalchemy.Integer,
        sqlalchemy.ForeignKey('auth_id.id'),
        primary_key=True,  # kind a sql-alchemy problem: model must have pk
    )
    facebook_id = sqlalchemy.Column(
        sqlalchemy.String(120),
        unique=True,
        index=True,
    )
    hashed = sqlalchemy.Column(
        sqlalchemy.String(sfcd.misc.Crypto.hashed_length)
    )
    salt = sqlalchemy.Column(
        sqlalchemy.String(sfcd.misc.Crypto.salt_length)
    )


########################################
# Manager
########################################

class Manager(sfcd.db.sql.base.ManagerBase):
    """
    Process all auth models in one manager
    """

    def __init__(self, *args, **kwargs):
        super(Manager, self).__init__(*args, **kwargs)
        #
        self.simple = self.SimpleMethod(self)
        self.facebook = self.FacebookMethod(self)

    class BaseMethod(object):
        # fill empty auth token with zeros
        # to prevent db fragmentation on future insert real auth token
        AUTH_TOKEN_MOCK = '0' * ID.auth_token.property.columns[0].type.length

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
            if len(email) > ID.email.property.columns[0].type.length:
                raise sfcd.db.exc.AuthError('email too long')

        @classmethod
        def _create_id_obj(cls, email):
            """
            Special method for ID record creation
            Fill auth_key with mock to prevent db fragmentation
            """
            return ID(
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
                id_obj.auth_token = sfcd.misc.Crypto.generate_auth_token()
                # check here for TTL and so on
                return True
            return False

    class SimpleMethod(BaseMethod):
        """
        Simple auth method db processor
        """

        # rewrite it to specific errors
        # TimeoutError
        # IntegrityError - non-unique value
        # retry IntegrityError will raise AuthError
        @sfcd.misc.retry((sqlalchemy.exc.SQLAlchemyError,), logger=logger)
        def register(self, email, password):
            """
            add simple auth record
            raises on invalid or non-unique email
            """
            # validate email - raises on error
            self._validate_email(email)
            # hash token to store in db
            hashed, salt = sfcd.misc.Crypto.hash_passphrase(password)
            # connect to database and start transaction
            with self.manager.session_scope() as session:
                # check for email in database
                # to prevent IntegrityError and raise human-readable exception
                if session.query(sqlalchemy.sql.exists().where(
                        ID.email == email)).scalar():
                    raise sfcd.db.exc.AuthError(
                        'email "{}" exists'.format(email))
                # add id and simple records to db
                id_obj = self._create_id_obj(email)
                session.add(id_obj)
                session.flush()  # make insert to get id_obj.id
                simple_obj = Simple(
                    auth_id=id_obj.id,
                    hashed=hashed,
                    salt=salt,
                )
                session.add(simple_obj)
                #
                logger.info('Insert "%s"', email)

        # rewrite it to specific errors
        # TimeoutError
        @sfcd.misc.retry((sqlalchemy.exc.SQLAlchemyError,), logger=logger)
        def get_auth_token(self, email, password):
            """
            get token via sipmle auth
            raises on errors
            """
            # validate email - raises on error
            self._validate_email(email)
            # connect to database and start transaction
            with self.manager.session_scope() as session:
                # get id and simple records
                # using SELECT .. FOR UPDATE to prevent
                # simultaneously auth_token updates
                objs = session.query(ID, Simple).join(Simple).filter(
                    ID.email == email).with_for_update(read=False).first()
                # raises if specified not found
                if not objs:
                    raise sfcd.db.exc.AuthError(
                        'email "{}" not exists'.format(email))
                #
                id_obj, session_obj = objs
                # validate specified password and db data - raises on error
                if not sfcd.misc.Crypto.validate_passphrase(
                        password, session_obj.hashed, session_obj.salt):
                    raise sfcd.db.exc.AuthError('invalid password')
                # update auth_token if needed
                if self.update_auth_token(id_obj):
                    session.add(id_obj)
                    logger.info(
                        'Update auth_token for "%s": %s',
                        email, id_obj.auth_token
                    )
                #
                return id_obj.auth_token

    class FacebookMethod(BaseMethod):
        """
        Facebook auth method db processor
        """

        @staticmethod
        def _validate_facebook_id(facebook_id):
            """
            validate facebook_id length bounds: (0..max_length]
            raises on error
            """
            if not facebook_id:
                raise sfcd.db.exc.AuthError('empty facebook_id')
            # way to get max field length
            if len(facebook_id) > \
                    Facebook.facebook_id.property.columns[0].type.length:
                raise sfcd.db.exc.AuthError('facebook_id too long')

        # rewrite it to specific errors
        # TimeoutError
        # IntegrityError - non-unique value
        # retry IntegrityError will raise AuthError
        @sfcd.misc.retry((sqlalchemy.exc.SQLAlchemyError,), logger=logger)
        def register(self, email, facebook_id, facebook_token):
            """
            add facebook auth record
            raises on invalid or non-unique email or facebook_id
            """
            # validate email - raises on error
            self._validate_email(email)
            # validate facebook_id - raises on error
            self._validate_facebook_id(facebook_id)
            # hash token to store in db
            hashed, salt = sfcd.misc.Crypto.hash_passphrase(facebook_token)
            # connect to database and start transaction
            with self.manager.session_scope() as session:
                # check for email in database because (unique=True)
                # to prevent IntegrityError and raise human-readable exception
                if session.query(sqlalchemy.sql.exists().where(
                        ID.email == email)).scalar():
                    raise sfcd.db.exc.AuthError(
                        'email "{}" exists'.format(email))
                # check for facebook_id in database because (unique=True)
                # same reason
                if session.query(sqlalchemy.sql.exists().where(
                        Facebook.facebook_id == facebook_id)).scalar():
                    raise sfcd.db.exc.AuthError(
                        'facebook_id "{}" exists'.format(facebook_id))
                # add id and facebook records to db
                id_obj = self._create_id_obj(email)
                session.add(id_obj)
                session.flush()  # make insert to get id_obj.id
                facebook_obj = Facebook(
                    auth_id=id_obj.id,
                    facebook_id=facebook_id,
                    hashed=hashed,
                    salt=salt,
                )
                session.add(facebook_obj)
                #
                logger.info('Insert "%s" for "%s"', email, facebook_id)

        # rewrite it to specific errors
        # TimeoutError
        @sfcd.misc.retry((sqlalchemy.exc.SQLAlchemyError,), logger=logger)
        def get_auth_token(self, email, facebook_id, facebook_token):
            """
            get token via facebook auth
            raises on errors
            """
            # validate email - raises on error
            self._validate_email(email)
            # validate facebook_id - raises on error
            self._validate_facebook_id(facebook_id)
            # connect to database and start transaction
            with self.manager.session_scope() as session:
                # check for email in database - raises if not exists
                if not session.query(sqlalchemy.sql.exists().where(
                        ID.email == email)).scalar():
                    raise sfcd.db.exc.AuthError(
                        'email "{}" not exists'.format(email))
                # get id and facebook records
                # using SELECT .. FOR UPDATE to prevent
                # simultaneously auth_token updates
                objs = session.query(ID, Facebook).join(Facebook).filter(
                    sqlalchemy.sql.expression.and_(
                        ID.email == email,
                        Facebook.facebook_id == facebook_id,
                    )).with_for_update(read=False).first()
                # raises if specified email and facebook_in not found
                if not objs:
                    raise sfcd.db.exc.AuthError(
                        'facebook_id "{}" not exists'.format(facebook_id))
                #
                id_obj, facebook_obj = objs
                # validate specified token and db data - raises on error
                if not sfcd.misc.Crypto.validate_passphrase(
                        facebook_token,
                        facebook_obj.hashed, facebook_obj.salt
                ):
                    raise sfcd.db.exc.AuthError('invalid passphrase')
                # update auth_token if needed
                if self.update_auth_token(id_obj):
                    session.add(id_obj)
                    logger.info(
                        'Update auth_token for "%s": %s',
                        email, id_obj.auth_token
                    )
                #
                return id_obj.auth_token
