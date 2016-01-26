import uuid

import pytest

import sqlalchemy.sql
import sqlalchemy.exc

import sfcd.db.sql.models.auth as auth_models


@pytest.fixture
def email():
    return '{}@example.com'.format(uuid.uuid4())


@pytest.fixture
def email_2():
    return '{}@example.com'.format(uuid.uuid4())


@pytest.fixture
def password():
    return str(uuid.uuid4())


@pytest.fixture
def facebook_id():
    return str(uuid.uuid4())


@pytest.fixture
def facebook_id_2():
    return str(uuid.uuid4())


@pytest.fixture
def facebook_token():
    return str(uuid.uuid4())


class TestAuth:
    def test__id(self, session, email):
        i = auth_models.ID(email=email)
        session.add(i)
        session.commit()
        i = session.query(auth_models.ID).filter_by(id=i.id).first()
        assert i.id is not None
        assert i.email == email

    def test__id__same_email(self, session, email):
        i_1 = auth_models.ID(email=email)
        i_2 = auth_models.ID(email=email)
        session.add_all([i_1, i_2])
        with pytest.raises(sqlalchemy.exc.IntegrityError):
            session.commit()

    def test__simple(self, session, email, password):
        i = auth_models.ID(email=email)
        session.add(i)
        session.flush()
        p = auth_models.Simple(auth_id=i.id, password=password)
        session.add(p)
        session.commit()
        p = session.query(auth_models.Simple).join(
            auth_models.ID).filter(
            auth_models.ID.email==email).one()
        assert p.password == password

    def test__rollback(self, session, email, password):
        i = auth_models.ID(email=email)
        session.add(i)
        session.flush()
        p = auth_models.Simple(auth_id=i.id, password=password)
        session.add(p)
        session.flush()
        session.rollback()
        assert not session.query(sqlalchemy.sql.exists().where(
            auth_models.ID.email==email)).scalar()
        assert not session.query(sqlalchemy.sql.exists().where(
            auth_models.Simple.password==password)).scalar()

    def test__simple__same_id(self, session, email, password):
        i = auth_models.ID(email=email)
        session.add(i)
        session.flush()
        p_1 = auth_models.Simple(auth_id=i.id, password=password)
        p_2 = auth_models.Simple(auth_id=i.id, password=password)
        session.add_all([p_1, p_2])
        with pytest.raises(sqlalchemy.exc.IntegrityError):
            session.commit()

    def test__facebook(self, session, email, facebook_id, facebook_token):
        i = auth_models.ID(email=email)
        session.add(i)
        session.flush()
        f = auth_models.Facebook(
            auth_id=i.id, facebook_id=facebook_id, facebook_token=facebook_token)
        session.add(f)
        session.commit()
        f = session.query(auth_models.Facebook).join(
            auth_models.ID).filter(
            auth_models.ID.email==email).one()
        assert f.facebook_id == facebook_id
        assert f.facebook_token == facebook_token

    def test__facebook__same_id(self, session, email, facebook_id, facebook_id_2, facebook_token):
        i = auth_models.ID(email=email)
        session.add(i)
        session.flush()
        f_1 = auth_models.Facebook(
            auth_id=i.id, facebook_id=facebook_id, facebook_token=facebook_token)
        f_2 = auth_models.Facebook(
            auth_id=i.id, facebook_id=facebook_id_2, facebook_token=facebook_token)
        session.add_all([f_1, f_2])
        with pytest.raises(sqlalchemy.exc.IntegrityError):
            session.commit()

    def test__facebook__same_facebook_id(self, session, email, email_2, facebook_id, facebook_token):
        i_1 = auth_models.ID(email=email)
        i_2 = auth_models.ID(email=email_2)
        session.add_all([i_1, i_2])
        session.flush()
        f_1 = auth_models.Facebook(
            auth_id=i_1.id, facebook_id=facebook_id, facebook_token=facebook_token)
        f_2 = auth_models.Facebook(
            auth_id=i_2.id, facebook_id=facebook_id, facebook_token=facebook_token)
        session.add_all([f_1, f_2])
        with pytest.raises(sqlalchemy.exc.IntegrityError):
            session.commit()
