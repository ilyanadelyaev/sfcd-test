import sqlalchemy
import sqlalchemy.sql
import sqlalchemy.sql.expression

import sfcd.db.sql


########################################
# Models
########################################

class ID(sfcd.db.sql.BaseModel):
    """
    "id" is system wide auth_id
    "email" must be unique
    """
    __tablename__ = 'auth_id'

    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
    email = sqlalchemy.Column(sqlalchemy.String(60), unique=True)


class Simple(sfcd.db.sql.BaseModel):
    """
    "password" and "salt" for simple auth method
    """
    __tablename__ = 'auth_simple'

    auth_id = sqlalchemy.Column(
        sqlalchemy.Integer,
        sqlalchemy.ForeignKey('auth_id.id'),
        primary_key=True,  # hack
    )
    password = sqlalchemy.Column(sqlalchemy.String(200))
    salt = sqlalchemy.Column(sqlalchemy.String(32))  # uuid4.hex


class Facebook(sfcd.db.sql.BaseModel):
    """
    "facebook_id" and "facebook_token" for auth via facebook
    facebook_id is unuque
    """
    __tablename__ = 'auth_facebook'

    auth_id = sqlalchemy.Column(
        sqlalchemy.Integer,
        sqlalchemy.ForeignKey('auth_id.id'),
        primary_key=True,  # hack
    )
    facebook_id = sqlalchemy.Column(sqlalchemy.String(120), unique=True)
    facebook_token = sqlalchemy.Column(sqlalchemy.String)


########################################
# Manager
########################################

class AuthManager(sfcd.db.sql.ManagerBase):
    def auth_exists(self, email):
        """
        check if auth exists in system
        """
        session = self.get_session()
        #
        return bool(
            session.query(sqlalchemy.sql.exists().where(
                ID.email==email)).scalar()
        )

    def add_simple_auth(self, email, password, salt):
        """
        add simple auth record
        """
        if not email:
            raise AttributeError('Empty email param')
        #
        session = self.get_session()
        #
        i = ID(email=email)
        session.add(i)
        session.flush()
        p = Simple(auth_id=i.id, password=password, salt=salt)
        session.add(p)
        session.commit()

    def check_simple_auth(self, email, password, salt):
        """
        check simple auth record
        """
        #
        session = self.get_session()
        #
        q = session.query(Simple).join(ID).filter(
            sqlalchemy.sql.expression.and_(
                ID.email==email,
                Simple.password==password,
                Simple.salt==salt,
            )
        )
        return bool(session.query(q.exists()).scalar())

    def add_facebook_auth(self, email, facebook_id, facebook_token):
        """
        add facebook auth record
        """
        if not facebook_id:
            raise AttributeError('Empty facebook_id param')
        #
        session = self.get_session()
        #
        i = ID(email=email)
        session.add(i)
        session.flush()
        f = Facebook(
            auth_id=i.id, facebook_id=facebook_id, facebook_token=facebook_token)
        session.add(f)
        session.commit()

    def check_facebook_auth(self, email, facebook_id, facebook_token):
        """
        check facebook auth method
        """
        #
        session = self.get_session()
        #
        q = session.query(Facebook).join(ID).filter(
            sqlalchemy.sql.expression.and_(
                ID.email==email,
                Facebook.facebook_id==facebook_id,
                Facebook.facebook_token==facebook_token,
            )
        )
        return bool(session.query(q.exists()).scalar())