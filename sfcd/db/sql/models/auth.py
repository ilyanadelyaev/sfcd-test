import sqlalchemy

import sfcd.db.sql


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
    "password" for simple auth method
    """
    __tablename__ = 'auth_simple'

    auth_id = sqlalchemy.Column(
        sqlalchemy.Integer,
        sqlalchemy.ForeignKey('auth_id.id'),
        primary_key=True,  # hack
    )
    password = sqlalchemy.Column(sqlalchemy.String(100))


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
