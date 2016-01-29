import sqlalchemy
import sqlalchemy.sql
import sqlalchemy.sql.expression

import sfcd.misc
import sfcd.db.exc
import sfcd.db.sql.base


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
        sqlalchemy.String(sfcd.misc.Crypto.auth_token_length),
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
        sqlalchemy.String(sfcd.misc.Crypto.salt_lenght)
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
        sqlalchemy.String(sfcd.misc.Crypto.salt_lenght)
    )


########################################
# Manager
########################################

class AuthManager(sfcd.db.sql.base.ManagerBase):
    @staticmethod
    def _validate_email(email):
        """
        validate email lenght bounds: (0..max_length]
        raises on error
        """
        if not email:
            raise sfcd.db.exc.AuthError('empty email')
        # way to get max field length
        if len(email) > ID.email.property.columns[0].type.length:
            raise sfcd.db.exc.AuthError('email too long')

    @staticmethod
    def _validate_facebook_id(facebook_id):
        """
        validate facebook_id lenght bounds: (0..max_length]
        raises on error
        """
        if not facebook_id:
            raise sfcd.db.exc.AuthError('empty facebook_id')
        # way to get max field length
        if len(facebook_id) > \
                Facebook.facebook_id.property.columns[0].type.length:
            raise sfcd.db.exc.AuthError('facebook_id too long')

    def email_exists(self, email):
        """
        check if email exists in system
        """
        # validate email - raises on error
        self._validate_email(email)
        # connect to database and start transaction
        session = self.get_session()
        # check for email record in db
        return bool(
            session.query(sqlalchemy.sql.exists().where(
                ID.email == email)).scalar()
        )

    def register_simple_auth(self, email, password):
        """
        add simple auth record
        raises on invalid or non-unique email
        """
        # validate email - raises on error
        self._validate_email(email)
        # hash token to store in db
        hashed, salt = sfcd.misc.Crypto.hash_passphrase(password)
        # connect to database and start transaction
        session = self.get_session()
        # check for email in database
        # to prevent IntegrityError and raise human-readable exception
        if session.query(sqlalchemy.sql.exists().where(
                ID.email == email)).scalar():
            raise sfcd.db.exc.AuthError(
                'email "{}" exists'.format(email))
        # add id and simple records to db and commit
        i = ID(email=email)
        session.add(i)
        session.flush()  # make insert to get i.id
        p = Simple(
            auth_id=i.id,
            hashed=hashed,
            salt=salt,
        )
        session.add(p)
        session.commit()

    def get_token_simple_auth(self, email, password):
        """
        get token via sipmle auth
        raises on errors
        """
        # validate email - raises on error
        self._validate_email(email)
        # connect to database and start transaction
        session = self.get_session()
        # get id and simple records for specified parameters
        obj = session.query(ID, Simple).join(Simple).filter(
            ID.email == email).first()
        # raises if specified not found
        if not obj:
            raise sfcd.db.exc.AuthError(
                'email "{}" not exists'.format(email))
        #
        i, s = obj
        # validate specified password and db data - raises on error
        if not sfcd.misc.Crypto.validate_passphrase(
                password, s.hashed, s.salt):
            raise sfcd.db.exc.AuthError('invalid password')
        # generate auth_token if needed
        # ? what about ttl
        if not i.auth_token:
            i.auth_token = sfcd.misc.Crypto.generate_auth_token()
            session.add(i)
            session.commit()
        #
        return i.auth_token

    def register_facebook_auth(self, email, facebook_id, facebook_token):
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
        session = self.get_session()
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
        # add id and facebook records to db and commit
        i = ID(email=email)
        session.add(i)
        session.flush()  # make insert to get i.id
        f = Facebook(
            auth_id=i.id,
            facebook_id=facebook_id,
            hashed=hashed,
            salt=salt,
        )
        session.add(f)
        session.commit()

    def get_token_facebook_auth(self, email, facebook_id, facebook_token):
        """
        get token via facebook auth
        raises on errors
        """
        # validate email - raises on error
        self._validate_email(email)
        # validate facebook_id - raises on error
        self._validate_facebook_id(facebook_id)
        # connect to database and start transaction
        session = self.get_session()
        # check for email in database - raises if not exists
        if not session.query(sqlalchemy.sql.exists().where(
                ID.email == email)).scalar():
            raise sfcd.db.exc.AuthError(
                'email "{}" not exists'.format(email))
        # get id and facebook records for specified parameters
        obj = session.query(ID, Facebook).join(Facebook).filter(
            sqlalchemy.sql.expression.and_(
                ID.email == email,
                Facebook.facebook_id == facebook_id,
            )).first()
        # raises if specified email and facebook_in not found
        if not obj:
            raise sfcd.db.exc.AuthError(
                'facebook_id "{}" not exists'.format(facebook_id))
        #
        i, f = obj
        # validate specified token and db data - raises on error
        if not sfcd.misc.Crypto.validate_passphrase(
                facebook_token, f.hashed, f.salt):
            raise sfcd.db.exc.AuthError('invalid passphrase')
        # generate auth_token if needed
        # ? what about ttl
        if not i.auth_token:
            i.auth_token = sfcd.misc.Crypto.generate_auth_token()
            session.add(i)
            session.commit()
        #
        return i.auth_token
