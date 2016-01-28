import sqlalchemy
import sqlalchemy.sql
import sqlalchemy.sql.expression

import sfcd.misc
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


class Simple(sfcd.db.sql.base.BaseModel):
    """
    :hashed: and :salt: to securely store user password
    """
    __tablename__ = 'auth_simple'

    auth_id = sqlalchemy.Column(
        sqlalchemy.Integer,
        sqlalchemy.ForeignKey('auth_id.id'),
        primary_key=True,  # hack
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
        primary_key=True,  # hack
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

    def facebook_id_exists(self, facebook_id):
        """
        check if facebook_id exists in system
        """
        session = self.get_session()
        #
        return bool(
            session.query(sqlalchemy.sql.exists().where(
                Facebook.facebook_id == facebook_id)).scalar()
        )

    def add_simple_auth(self, email, password):
        """
        add simple auth record
        """
        if not email:
            raise AttributeError('Empty email param')
        #
        session = self.get_session()
        #
        hashed, salt = sfcd.misc.Crypto.hash_passphrase(password)
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

    def check_simple_auth(self, email, password):
        """
        check simple auth record
        """
        #
        session = self.get_session()
        #
        obj = session.query(Simple).join(ID).filter(
            ID.email == email).first()
        if not obj:
            return False
        #
        return sfcd.misc.Crypto.validate_passphrase(
            password, obj.hashed, obj.salt)

    def add_facebook_auth(self, email, facebook_id, facebook_token):
        """
        add facebook auth record
        """
        if not email:
            raise AttributeError('Empty email param')
        if not facebook_id:
            raise AttributeError('Empty facebook_id param')
        #
        session = self.get_session()
        #
        hashed, salt = sfcd.misc.Crypto.hash_passphrase(facebook_token)
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

    def check_facebook_auth(self, email, facebook_id, facebook_token):
        """
        check facebook auth method
        """
        #
        session = self.get_session()
        #
        obj = session.query(Facebook).join(ID).filter(
            sqlalchemy.sql.expression.and_(
                ID.email == email,
                Facebook.facebook_id == facebook_id,
            )).first()
        if not obj:
            return False
        #
        return sfcd.misc.Crypto.validate_passphrase(
            facebook_token, obj.hashed, obj.salt)
