import logging

import sqlalchemy

import sfcd.db.sql.base
import sfcd.misc.retry
import sfcd.misc.crypto

import sfcd.db.sql.auth.base


logger = logging.getLogger('sfcd')


class Model(sfcd.db.sql.base.BaseModel):
    """
    :hashed: and :salt: to securely store user password
    """
    __tablename__ = 'auth_simple'

    auth_id = sqlalchemy.Column(
        sqlalchemy.Integer,
        sqlalchemy.ForeignKey('auth_base.id'),
        primary_key=True,  # kind a sql-alchemy problem: model must have pk
    )
    hashed = sqlalchemy.Column(
        sqlalchemy.String(sfcd.misc.crypto.Crypto.hashed_length)
    )
    salt = sqlalchemy.Column(
        sqlalchemy.String(sfcd.misc.crypto.Crypto.salt_length)
    )


class SimpleMethod(sfcd.db.sql.auth.base.BaseMethod):
    """
    Simple auth method db processor
    """

    # rewrite it to specific errors
    # TimeoutError
    # IntegrityError - non-unique value
    # retry IntegrityError will raise AuthError
    @sfcd.misc.retry.retry((sqlalchemy.exc.SQLAlchemyError,), logger=logger)
    def register(self, email, password):
        """
        add simple auth record
        raises on invalid or non-unique email
        """
        # validate email - raises on error
        self._validate_email(email)
        # hash token to store in db
        hashed, salt = sfcd.misc.crypto.Crypto.hash_passphrase(password)
        # connect to database and start transaction
        with self.manager.session_scope() as session:
            # check for email in database
            # to prevent IntegrityError and raise human-readable exception
            if session.query(sqlalchemy.sql.exists().where(
                    sfcd.db.sql.auth.base.Model.email == email)).scalar():
                raise sfcd.db.exc.AuthError(
                    'email "{}" exists'.format(email))
            # add id and simple records to db
            id_obj = self._create_id_obj(email)
            session.add(id_obj)
            session.flush()  # make insert to get id_obj.id
            simple_obj = Model(
                auth_id=id_obj.id,
                hashed=hashed,
                salt=salt,
            )
            session.add(simple_obj)
            #
            logger.info('Insert "%s"', email)

    # rewrite it to specific errors
    # TimeoutError
    @sfcd.misc.retry.retry((sqlalchemy.exc.SQLAlchemyError,), logger=logger)
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
            objs = session.query(
                sfcd.db.sql.auth.base.Model, Model).join(Model).filter(
                    sfcd.db.sql.auth.base.Model.email == email
                ).with_for_update(read=False).first()
            # raises if specified not found
            if not objs:
                raise sfcd.db.exc.AuthError(
                    'email "{}" not exists'.format(email))
            #
            id_obj, session_obj = objs
            # validate specified password and db data - raises on error
            if not sfcd.misc.crypto.Crypto.validate_passphrase(
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
