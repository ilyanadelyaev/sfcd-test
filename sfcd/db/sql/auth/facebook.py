import logging

import sqlalchemy

import sfcd.db.sql.base
import sfcd.misc

import sfcd.db.sql.auth.base


logger = logging.getLogger('sfcd')


class Model(sfcd.db.sql.base.BaseModel):
    """
    :facebook_id: unique facebook user identifier
    :hashed: and :salt: to securely store facebook_token
    """
    __tablename__ = 'auth_facebook'

    auth_id = sqlalchemy.Column(
        sqlalchemy.Integer,
        sqlalchemy.ForeignKey('auth_base.id'),
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


class FacebookMethod(sfcd.db.sql.auth.base.BaseMethod):
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
                Model.facebook_id.property.columns[0].type.length:
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
                    sfcd.db.sql.auth.base.Model.email == email)).scalar():
                raise sfcd.db.exc.AuthError(
                    'email "{}" exists'.format(email))
            # check for facebook_id in database because (unique=True)
            # same reason
            if session.query(sqlalchemy.sql.exists().where(
                    Model.facebook_id == facebook_id)).scalar():
                raise sfcd.db.exc.AuthError(
                    'facebook_id "{}" exists'.format(facebook_id))
            # add id and facebook records to db
            id_obj = self._create_id_obj(email)
            session.add(id_obj)
            session.flush()  # make insert to get id_obj.id
            facebook_obj = Model(
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
                    sfcd.db.sql.auth.base.Model.email == email)).scalar():
                raise sfcd.db.exc.AuthError(
                    'email "{}" not exists'.format(email))
            # get id and facebook records
            # using SELECT .. FOR UPDATE to prevent
            # simultaneously auth_token updates
            objs = session.query(
                sfcd.db.sql.auth.base.Model, Model).join(Model).filter(
                sqlalchemy.sql.expression.and_(
                    sfcd.db.sql.auth.base.Model.email == email,
                    Model.facebook_id == facebook_id,
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
