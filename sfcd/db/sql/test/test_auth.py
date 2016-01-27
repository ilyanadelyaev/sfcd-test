import uuid

import pytest

import sqlalchemy.sql
import sqlalchemy.sql.expression
import sqlalchemy.exc

import sfcd.db.sql.auth


########################################
# fixtures
########################################

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


@pytest.fixture(scope='session')
def auth_manager(session_maker):
    return sfcd.db.sql.auth.AuthManager(session_maker)


########################################
# test models
########################################

class TestModels:
    def test__id(self, session, email):
        """
        test auth creation
        """
        i = sfcd.db.sql.auth.ID(email=email)
        session.add(i)
        session.commit()
        i = session.query(sfcd.db.sql.auth.ID).filter_by(id=i.id).first()
        assert i.id is not None
        assert i.email == email

    def test__id__same_email(self, session, email):
        """
        test auth creation with same email
        """
        i_1 = sfcd.db.sql.auth.ID(email=email)
        i_2 = sfcd.db.sql.auth.ID(email=email)
        session.add_all([i_1, i_2])
        with pytest.raises(sqlalchemy.exc.IntegrityError):
            session.commit()

    def test__simple(self, session, email, password):
        """
        test simple auth creation
        """
        i = sfcd.db.sql.auth.ID(email=email)
        session.add(i)
        session.flush()
        p = sfcd.db.sql.auth.Simple(auth_id=i.id, password=password)
        session.add(p)
        session.commit()
        p = session.query(sfcd.db.sql.auth.Simple).join(
            sfcd.db.sql.auth.ID).filter(
            sfcd.db.sql.auth.ID.email==email).one()
        assert p.password == password

    def test__rollback(self, session, email, password):
        """
        test rollback for auth records
        """
        i = sfcd.db.sql.auth.ID(email=email)
        session.add(i)
        session.flush()
        p = sfcd.db.sql.auth.Simple(auth_id=i.id, password=password)
        session.add(p)
        session.flush()
        session.rollback()
        assert not session.query(sqlalchemy.sql.exists().where(
            sfcd.db.sql.auth.ID.email==email)).scalar()
        assert not session.query(sqlalchemy.sql.exists().where(
            sfcd.db.sql.auth.Simple.password==password)).scalar()

    def test__simple__same_id(self, session, email, password):
        """
        test simple auth creation with same auth.id
        """
        i = sfcd.db.sql.auth.ID(email=email)
        session.add(i)
        session.flush()
        p_1 = sfcd.db.sql.auth.Simple(auth_id=i.id, password=password)
        p_2 = sfcd.db.sql.auth.Simple(auth_id=i.id, password=password)
        session.add_all([p_1, p_2])
        with pytest.raises(sqlalchemy.exc.IntegrityError):
            session.commit()

    def test__facebook(self, session, email, facebook_id, facebook_token):
        """
        test facebook auth creation
        """
        i = sfcd.db.sql.auth.ID(email=email)
        session.add(i)
        session.flush()
        f = sfcd.db.sql.auth.Facebook(
            auth_id=i.id, facebook_id=facebook_id, facebook_token=facebook_token)
        session.add(f)
        session.commit()
        f = session.query(sfcd.db.sql.auth.Facebook).join(
            sfcd.db.sql.auth.ID).filter(
            sfcd.db.sql.auth.ID.email==email).one()
        assert f.facebook_id == facebook_id
        assert f.facebook_token == facebook_token

    def test__facebook__same_id(self, session, email, facebook_id, facebook_id_2, facebook_token):
        """
        test facebook auth creation with same auth.id
        """
        i = sfcd.db.sql.auth.ID(email=email)
        session.add(i)
        session.flush()
        f_1 = sfcd.db.sql.auth.Facebook(
            auth_id=i.id, facebook_id=facebook_id, facebook_token=facebook_token)
        f_2 = sfcd.db.sql.auth.Facebook(
            auth_id=i.id, facebook_id=facebook_id_2, facebook_token=facebook_token)
        session.add_all([f_1, f_2])
        with pytest.raises(sqlalchemy.exc.IntegrityError):
            session.commit()

    def test__facebook__same_facebook_id(self, session, email, email_2, facebook_id, facebook_token):
        """
        test facebook auth creation with same facebook_id
        """
        i_1 = sfcd.db.sql.auth.ID(email=email)
        i_2 = sfcd.db.sql.auth.ID(email=email_2)
        session.add_all([i_1, i_2])
        session.flush()
        f_1 = sfcd.db.sql.auth.Facebook(
            auth_id=i_1.id, facebook_id=facebook_id, facebook_token=facebook_token)
        f_2 = sfcd.db.sql.auth.Facebook(
            auth_id=i_2.id, facebook_id=facebook_id, facebook_token=facebook_token)
        session.add_all([f_1, f_2])
        with pytest.raises(sqlalchemy.exc.IntegrityError):
            session.commit()


########################################
# test manager
########################################

class TestManager:
    def test__is_auth__exists(self, session, auth_manager, email):
        """
        check if auth exists in system
        """
        i = sfcd.db.sql.auth.ID(email=email)
        session.add(i)
        session.commit()
        #
        assert auth_manager._is_auth(email)

    def test__is_auth__not_exists(self, auth_manager, email):
        """
        check if auth not exists
        """
        assert not auth_manager._is_auth(email)

    def test__add_simple_auth(self, session, auth_manager, email, password):
        """
        add simple auth and check result
        """
        auth_manager.add_simple_auth(email, password)
        #
        q = session.query(
            sfcd.db.sql.auth.Simple).join(sfcd.db.sql.auth.ID).filter(
                sqlalchemy.sql.expression.and_(
                    sfcd.db.sql.auth.ID.email==email,
                    sfcd.db.sql.auth.Simple.password==password,
                )
        )
        assert session.query(q.exists()).scalar()

    def test__add_simple_auth__empty_email(self, auth_manager, password):
        """
        add simple auth with empty email
        """
        with pytest.raises(AttributeError):
            auth_manager.add_simple_auth('', password)
        with pytest.raises(AttributeError):
            auth_manager.add_simple_auth(None, password)

    def test__check_simple_auth(self, auth_manager, email, password, session):
        """
        test if simple auth exists
        """
        i = sfcd.db.sql.auth.ID(email=email)
        session.add(i)
        session.flush()
        p = sfcd.db.sql.auth.Simple(auth_id=i.id, password=password)
        session.add(p)
        session.commit()
        #
        assert auth_manager.check_simple_auth(email, password)

    def test__check_simple_auth__not_exists(
            self, auth_manager, email, password, session):
        """
        test if simple auth not exists
        """
        i = sfcd.db.sql.auth.ID(email=email)
        session.add(i)
        session.flush()
        p = sfcd.db.sql.auth.Simple(auth_id=i.id, password=password)
        session.add(p)
        session.commit()
        #
        assert not auth_manager.check_simple_auth(email, '')
        assert not auth_manager.check_simple_auth('', password)
        assert not auth_manager.check_simple_auth('', '')

    def test__add_facebook_auth(
            self, session, auth_manager, email, facebook_id, facebook_token):
        """
        add facebook auth and check result
        """
        auth_manager.add_facebook_auth(email, facebook_id, facebook_token)
        #
        q = session.query(
            sfcd.db.sql.auth.Facebook).join(sfcd.db.sql.auth.ID).filter(
                sqlalchemy.sql.expression.and_(
                    sfcd.db.sql.auth.ID.email==email,
                    sfcd.db.sql.auth.Facebook.facebook_id==facebook_id,
                    sfcd.db.sql.auth.Facebook.facebook_token==facebook_token,
                )
        )
        assert session.query(q.exists()).scalar()

    def test__add_facebook_auth__empty_facebook_id(
            self, session, auth_manager, email, facebook_token):
        """
        add simple auth and check result
        """
        with pytest.raises(AttributeError):
            auth_manager.add_facebook_auth(email, '', facebook_token)
        with pytest.raises(AttributeError):
            auth_manager.add_facebook_auth(email, None, facebook_token)

    def test__check_facebook_auth(
            self, session, auth_manager, email, facebook_id, facebook_token):
        """
        """
        i = sfcd.db.sql.auth.ID(email=email)
        session.add(i)
        session.flush()
        f = sfcd.db.sql.auth.Facebook(
            auth_id=i.id, facebook_id=facebook_id, facebook_token=facebook_token)
        session.add(f)
        session.commit()
        #
        assert auth_manager.check_facebook_auth(email, facebook_id, facebook_token)

    def test__check_facebook_auth__not_exists(
            self, session, auth_manager, email, facebook_id, facebook_token):
        """
        """
        i = sfcd.db.sql.auth.ID(email=email)
        session.add(i)
        session.flush()
        f = sfcd.db.sql.auth.Facebook(
            auth_id=i.id, facebook_id=facebook_id, facebook_token=facebook_token)
        session.add(f)
        session.commit()
        #
        assert not auth_manager.check_facebook_auth(email, facebook_id, '')
        assert not auth_manager.check_facebook_auth(email, '', facebook_token)
        assert not auth_manager.check_facebook_auth(email, '', '')
        assert not auth_manager.check_facebook_auth('', facebook_id, '')
        assert not auth_manager.check_facebook_auth('', '', facebook_token)
        assert not auth_manager.check_facebook_auth('', '', '')
