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
    def email_exists(self, email):
        """
        check if email exists in system
        """
        session = self.get_session()
        #
        return bool(
            session.query(sqlalchemy.sql.exists().where(
                ID.email == email)).scalar()
        )

    def register_simple_auth(self, email, password):
        """
        add simple auth record
        raises on empty or non-unique email
        """
        if not email:
            raise sfcd.db.exc.AuthError('empty email param')
        #
        hashed, salt = sfcd.misc.Crypto.hash_passphrase(password)
        #
        session = self.get_session()
        # check for email in database
        # to prevent IntegrityError and raise human-readable exception
        if session.query(sqlalchemy.sql.exists().where(
                ID.email == email)).scalar():
            raise sfcd.db.exc.AuthError(
                'email "{}" exists'.format(email))
        #
        i = ID(email=email)
        session.add(i)
        session.flush()
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
        raises on error
        """
        #
        session = self.get_session()
        #
        obj = session.query(ID, Simple).join(Simple).filter(
            ID.email == email).first()
        if not obj:
            raise sfcd.db.exc.AuthError(
                'email "{}" not exists'.format(email))
        #
        i, s = obj
        #
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
        raises on empty or non-unique email or facebook_id
        """
        if not email:
            raise sfcd.db.exc.AuthError('empty email param')
        if not facebook_id:
            raise sfcd.db.exc.AuthError('empty facebook_id param')
        #
        hashed, salt = sfcd.misc.Crypto.hash_passphrase(facebook_token)
        #
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
        #
        i = ID(email=email)
        session.add(i)
        session.flush()
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
        raises on error
        """
        #
        session = self.get_session()
        #
        if not session.query(sqlalchemy.sql.exists().where(
                ID.email == email)).scalar():
            raise sfcd.db.exc.AuthError(
                'email "{}" not exists'.format(email))
        #
        obj = session.query(ID, Facebook).join(Facebook).filter(
            sqlalchemy.sql.expression.and_(
                ID.email == email,
                Facebook.facebook_id == facebook_id,
            )).first()
        if not obj:
            raise sfcd.db.exc.AuthError(
                'facebook_id "{}" not exists'.format(facebook_id))
        #
        i, f = obj
        #
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
