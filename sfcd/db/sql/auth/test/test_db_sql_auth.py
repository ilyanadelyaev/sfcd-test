import pytest

import sqlalchemy.exc

import sfcd.misc.crypto
import sfcd.db.sql.auth.base
import sfcd.db.sql.auth.simple
import sfcd.db.sql.auth.facebook
import sfcd.db.sql.auth.manager


@pytest.fixture(scope='session')
def manager(session_maker):
    return sfcd.db.sql.auth.manager.Manager(session_maker)


class TestIDModel:
    def test__id(self, session_scope, email, auth_token):
        """
        test auth creation
        """
        with session_scope() as session:
            i = sfcd.db.sql.auth.base.Model(
                email=email,
                auth_token=auth_token,
            )
            session.add(i)
            session.flush()
            i = session.query(
                sfcd.db.sql.auth.base.Model
            ).filter_by(id=i.id).first()
            assert i.id is not None
            assert i.email == email
            assert i.auth_token == auth_token

    def test__id__same_email(self, session_scope, email):
        """
        test auth creation with same email
        """
        with pytest.raises(sqlalchemy.exc.IntegrityError):
            with session_scope() as session:
                i_1 = sfcd.db.sql.auth.base.Model(email=email)
                i_2 = sfcd.db.sql.auth.base.Model(email=email)
                session.add_all([i_1, i_2])


class TestSimpleModel:
    def test__simple(self, session_scope, email, password):
        """
        test simple auth creation
        """
        hashed, salt = sfcd.misc.crypto.Crypto.hash_passphrase(password)
        #
        with session_scope() as session:
            i = sfcd.db.sql.auth.base.Model(email=email)
            session.add(i)
            session.flush()
            p = sfcd.db.sql.auth.simple.Model(
                auth_id=i.id, hashed=hashed, salt=salt)
            session.add(p)
            session.flush()
            p = session.query(sfcd.db.sql.auth.simple.Model).join(
                sfcd.db.sql.auth.base.Model).filter(
                    sfcd.db.sql.auth.base.Model.email == email).one()
            assert p.hashed == hashed
            assert p.salt == salt

    def test__simple__same_id(self, session_scope, email, password):
        """
        test simple auth creation with same auth.id
        """
        hashed, salt = sfcd.misc.crypto.Crypto.hash_passphrase(password)
        #
        with pytest.raises(sqlalchemy.exc.IntegrityError):
            with session_scope() as session:
                i = sfcd.db.sql.auth.base.Model(email=email)
                session.add(i)
                session.flush()
                p_1 = sfcd.db.sql.auth.simple.Model(
                    auth_id=i.id, hashed=hashed, salt=salt)
                p_2 = sfcd.db.sql.auth.simple.Model(
                    auth_id=i.id, hashed=hashed, salt=salt)
                session.add_all([p_1, p_2])

    def test__simple__rollback(self, session_scope, email, password):
        """
        test rollback for auth records
        """
        hashed, salt = sfcd.misc.crypto.Crypto.hash_passphrase(password)
        #
        with session_scope() as session:
            i = sfcd.db.sql.auth.base.Model(email=email)
            session.add(i)
            session.flush()
            p = sfcd.db.sql.auth.simple.Model(
                auth_id=i.id, hashed=hashed, salt=salt)
            session.add(p)
            session.flush()
            session.rollback()
            assert not session.query(sqlalchemy.sql.exists().where(
                sfcd.db.sql.auth.base.Model.email == email)).scalar()
            assert not session.query(sqlalchemy.sql.exists().where(
                sfcd.db.sql.auth.simple.Model.hashed == hashed)).scalar()


class TestFacebookModel:
    def test__facebook(
            self, session_scope,
            email, facebook_id, facebook_token
    ):
        """
        test facebook auth creation
        """
        hashed, salt = sfcd.misc.crypto.Crypto.hash_passphrase(facebook_token)
        #
        with session_scope() as session:
            i = sfcd.db.sql.auth.base.Model(email=email)
            session.add(i)
            session.flush()
            f = sfcd.db.sql.auth.facebook.Model(
                auth_id=i.id,
                facebook_id=facebook_id,
                hashed=hashed,
                salt=salt,
            )
            session.add(f)
            session.flush()
            f = session.query(sfcd.db.sql.auth.facebook.Model).join(
                sfcd.db.sql.auth.base.Model).filter(
                    sfcd.db.sql.auth.base.Model.email == email).one()
            assert f.facebook_id == facebook_id
            assert f.hashed == hashed
            assert f.salt == salt

    def test__facebook__same_id(
            self, session_scope,
            email, facebook_id, facebook_id_2, facebook_token
    ):
        """
        test facebook auth creation with same auth.id
        """
        hashed, salt = sfcd.misc.crypto.Crypto.hash_passphrase(facebook_token)
        #
        with pytest.raises(sqlalchemy.exc.IntegrityError):
            with session_scope() as session:
                i = sfcd.db.sql.auth.base.Model(email=email)
                session.add(i)
                session.flush()
                f_1 = sfcd.db.sql.auth.facebook.Model(
                    auth_id=i.id,
                    facebook_id=facebook_id,
                    hashed=hashed,
                    salt=salt,
                )
                f_2 = sfcd.db.sql.auth.facebook.Model(
                    auth_id=i.id,
                    facebook_id=facebook_id_2,
                    hashed=hashed,
                    salt=salt,
                )
                session.add_all([f_1, f_2])

    def test__facebook__same_facebook_id(
            self, session_scope,
            email, email_2, facebook_id, facebook_token
    ):
        """
        test facebook auth creation with same facebook_id
        """
        hashed, salt = sfcd.misc.crypto.Crypto.hash_passphrase(facebook_token)
        #
        with pytest.raises(sqlalchemy.exc.IntegrityError):
            with session_scope() as session:
                i_1 = sfcd.db.sql.auth.base.Model(email=email)
                i_2 = sfcd.db.sql.auth.base.Model(email=email_2)
                session.add_all([i_1, i_2])
                session.flush()
                f_1 = sfcd.db.sql.auth.facebook.Model(
                    auth_id=i_1.id,
                    facebook_id=facebook_id,
                    hashed=hashed,
                    salt=salt,
                )
                f_2 = sfcd.db.sql.auth.facebook.Model(
                    auth_id=i_2.id,
                    facebook_id=facebook_id,
                    hashed=hashed,
                    salt=salt,
                )
                session.add_all([f_1, f_2])


class TestBaseMethod:
    def test__validate_email(self):
        with pytest.raises(sfcd.db.exc.AuthError) as ex_info:
            sfcd.db.sql.auth.base.BaseMethod._validate_email('')
        assert ex_info.value.message == 'empty email'
        #
        with pytest.raises(sfcd.db.exc.AuthError) as ex_info:
            sfcd.db.sql.auth.base.BaseMethod._validate_email(
                'e' * 61)
        assert ex_info.value.message == 'email too long'

    def test__create_id_obj(self):
        id_obj = sfcd.db.sql.auth.base.BaseMethod._create_id_obj('email')
        #
        assert id_obj.auth_token == \
            sfcd.db.sql.auth.base.BaseMethod.AUTH_TOKEN_MOCK

    def test__update_auth_token(self):
        id_obj = sfcd.db.sql.auth.base.BaseMethod._create_id_obj('email')
        # updated
        token = id_obj.auth_token
        assert sfcd.db.sql.auth.base.BaseMethod.update_auth_token(id_obj)
        assert id_obj.auth_token !=\
            sfcd.db.sql.auth.base.BaseMethod.AUTH_TOKEN_MOCK
        assert token != id_obj.auth_token
        # not updated
        token = id_obj.auth_token
        assert not \
            sfcd.db.sql.auth.base.BaseMethod.update_auth_token(id_obj)
        assert token == id_obj.auth_token

    def test__register(self):
        with pytest.raises(NotImplementedError):
            sfcd.db.sql.auth.base.BaseMethod(None).register()

    def test__get_auth_token(self):
        with pytest.raises(NotImplementedError):
            sfcd.db.sql.auth.base.BaseMethod(None).get_auth_token()


class TestSimpleMethod:
    def test__register__empty_email(self, manager, password):
        """
        register: empty email
        """
        with pytest.raises(sfcd.db.exc.AuthError) as ex_info:
            manager.simple.register('', password)
        assert str(ex_info.value) == 'empty email'
        with pytest.raises(sfcd.db.exc.AuthError) as ex_info:
            manager.simple.register(None, password)
        assert str(ex_info.value) == 'empty email'

    def test__register__email_too_long(self, manager):
        """
        register: email too long
        """
        with pytest.raises(sfcd.db.exc.AuthError) as ex_info:
            manager.simple.register('e' * 61, '')
        assert str(ex_info.value) == 'email too long'

    def test__register__email_exists(
            self, session_scope, manager,
            email, password
    ):
        """
        catch exception on existent email
        """
        hashed, salt = sfcd.misc.crypto.Crypto.hash_passphrase(password)
        #
        with session_scope() as session:
            i = sfcd.db.sql.auth.base.Model(email=email)
            session.add(i)
            session.flush()
            p = sfcd.db.sql.auth.simple.Model(
                auth_id=i.id, hashed=hashed, salt=salt)
            session.add(p)
        #
        with pytest.raises(sfcd.db.exc.AuthError) as ex_info:
            manager.simple.register(email, password)
        assert str(ex_info.value) == \
            'email "{}" exists'.format(email)

    def test__register(
            self, session_scope, manager,
            email, password
    ):
        """
        add simple auth and check result
        """
        manager.simple.register(email, password)
        # check
        with session_scope() as session:
            obj = session.query(
                sfcd.db.sql.auth.simple.Model).join(
                    sfcd.db.sql.auth.base.Model).filter(
                        sqlalchemy.sql.expression.and_(
                            sfcd.db.sql.auth.base.Model.email == email,
                        )
                ).first()
            assert obj
            assert sfcd.misc.crypto.Crypto.validate_passphrase(
                password, obj.hashed, obj.salt)

    def test__get_auth_token__empty_email(self, manager, password):
        """
        get_auth_token: empty email
        """
        with pytest.raises(sfcd.db.exc.AuthError) as ex_info:
            manager.simple.get_auth_token('', password)
        assert str(ex_info.value) == 'empty email'
        with pytest.raises(sfcd.db.exc.AuthError) as ex_info:
            manager.simple.get_auth_token(None, password)
        assert str(ex_info.value) == 'empty email'

    def test__get_auth_token__email_too_long(self, manager):
        """
        get_auth_token: email too long error
        """
        with pytest.raises(sfcd.db.exc.AuthError) as ex_info:
            manager.simple.get_auth_token('e' * 61, '')
        assert str(ex_info.value) == 'email too long'

    def test__get_auth_token__email_not_exists(
            self, manager,
            email, password
    ):
        """
        get_auth_token: email not exists
        """
        with pytest.raises(sfcd.db.exc.AuthError) as ex_info:
            manager.simple.get_auth_token('invalid', password)
        assert str(ex_info.value) == \
            'email "invalid" not exists'

    def test__get_auth_token__invalid_password(
            self, session_scope, manager,
            email, password
    ):
        """
        check invalid password
        """
        hashed, salt = sfcd.misc.crypto.Crypto.hash_passphrase(password)
        #
        with session_scope() as session:
            i = manager.simple._create_id_obj(email)
            session.add(i)
            session.flush()
            p = sfcd.db.sql.auth.simple.Model(
                auth_id=i.id, hashed=hashed, salt=salt)
            session.add(p)
        #
        with pytest.raises(sfcd.db.exc.AuthError) as ex_info:
            manager.simple.get_auth_token(email, 'invalid')
        assert str(ex_info.value) == \
            'invalid password'

    def test__get_auth_token(
            self, session_scope, manager,
            email, password
    ):
        """
        test if simple auth exists
        """
        hashed, salt = sfcd.misc.crypto.Crypto.hash_passphrase(password)
        #
        with session_scope() as session:
            i = manager.simple._create_id_obj(email)
            session.add(i)
            session.flush()
            p = sfcd.db.sql.auth.simple.Model(
                auth_id=i.id, hashed=hashed, salt=salt)
            session.add(p)
        # some token
        token = manager.simple.get_auth_token(email, password)
        assert len(token) == sfcd.misc.crypto.Crypto.auth_token_length
        assert token != sfcd.db.sql.auth.base.BaseMethod.AUTH_TOKEN_MOCK

    def test__get_auth_token__tokens_equal(
            self, session_scope, manager,
            email, password
    ):
        """
        test if simple auth exists
        """
        hashed, salt = sfcd.misc.crypto.Crypto.hash_passphrase(password)
        #
        with session_scope() as session:
            i = manager.simple._create_id_obj(email)
            session.add(i)
            session.flush()
            p = sfcd.db.sql.auth.simple.Model(
                auth_id=i.id, hashed=hashed, salt=salt)
            session.add(p)
        # check equal
        token_1 = manager.simple.get_auth_token(email, password)
        token_2 = manager.simple.get_auth_token(email, password)
        assert len(token_1) == sfcd.misc.crypto.Crypto.auth_token_length
        assert token_1 == token_2


class TestFacebookMethod:
    def test__register__empty_email(
            self, manager):
        """
        register: empty email error
        """
        with pytest.raises(sfcd.db.exc.AuthError) as ex_info:
            manager.facebook.register('', '', '')
        assert str(ex_info.value) == 'empty email'
        with pytest.raises(sfcd.db.exc.AuthError) as ex_info:
            manager.facebook.register(None, '', '')
        assert str(ex_info.value) == 'empty email'

    def test__register__email_too_long(
            self, manager, facebook_id):
        """
        register: email too long error
        """
        with pytest.raises(sfcd.db.exc.AuthError) as ex_info:
            manager.facebook.register('e' * 61, facebook_id, '')
        assert str(ex_info.value) == 'email too long'

    def test__register__empty_facebook_id(
            self, manager, email, facebook_token):
        """
        register: empty facebook_id error
        """
        with pytest.raises(sfcd.db.exc.AuthError) as ex_info:
            manager.facebook.register(email, '', facebook_token)
        assert str(ex_info.value) == 'empty facebook_id'
        with pytest.raises(sfcd.db.exc.AuthError) as ex_info:
            manager.facebook.register(email, None, facebook_token)
        assert str(ex_info.value) == 'empty facebook_id'

    def test__register__facebook_id_too_long(
            self, manager, email):
        """
        register: facebook_id too long error
        """
        with pytest.raises(sfcd.db.exc.AuthError) as ex_info:
            manager.facebook.register(email, 'f' * 121, '')
        assert str(ex_info.value) == 'facebook_id too long'

    def test__register__email_exists(
            self, session_scope, manager,
            email, facebook_id, facebook_token
    ):
        """
        register: email exists error
        """
        hashed, salt = sfcd.misc.crypto.Crypto.hash_passphrase(facebook_token)
        #
        with session_scope() as session:
            i = manager.simple._create_id_obj(email)
            session.add(i)
            session.flush()
            f = sfcd.db.sql.auth.facebook.Model(
                auth_id=i.id,
                facebook_id=facebook_id,
                hashed=hashed,
                salt=salt,
            )
            session.add(f)
        #
        with pytest.raises(sfcd.db.exc.AuthError) as ex_info:
            manager.facebook.register(
                email, facebook_id, facebook_token)
        assert str(ex_info.value) == \
            'email "{}" exists'.format(email)

    def test__register__facebook_id_exists(
            self, session_scope, manager,
            email, email_2, facebook_id, facebook_token
    ):
        """
        register: facebook_id exists error
        """
        hashed, salt = sfcd.misc.crypto.Crypto.hash_passphrase(facebook_token)
        #
        with session_scope() as session:
            i = manager.simple._create_id_obj(email)
            session.add(i)
            session.flush()
            f = sfcd.db.sql.auth.facebook.Model(
                auth_id=i.id,
                facebook_id=facebook_id,
                hashed=hashed,
                salt=salt,
            )
            session.add(f)
        #
        with pytest.raises(sfcd.db.exc.AuthError) as ex_info:
            manager.facebook.register(
                email_2, facebook_id, facebook_token)
        assert str(ex_info.value) == \
            'facebook_id "{}" exists'.format(facebook_id)

    def test__register(
            self, session_scope, manager,
            email, facebook_id, facebook_token
    ):
        """
        register: OK
        """
        manager.facebook.register(email, facebook_id, facebook_token)
        #
        with session_scope() as session:
            obj = session.query(
                sfcd.db.sql.auth.facebook.Model).join(
                    sfcd.db.sql.auth.base.Model).filter(
                        sqlalchemy.sql.expression.and_(
                            sfcd.db.sql.auth.base.Model.email ==
                            email,
                            sfcd.db.sql.auth.facebook.Model.facebook_id ==
                            facebook_id,
                        )
                ).first()
            assert obj
            assert sfcd.misc.crypto.Crypto.validate_passphrase(
                facebook_token, obj.hashed, obj.salt)

    def test__get_auth_token__empty_email(
            self, manager):
        """
        get_auth_token: empty email error
        """
        with pytest.raises(sfcd.db.exc.AuthError) as ex_info:
            manager.facebook.get_auth_token('', '', '')
        assert str(ex_info.value) == 'empty email'
        with pytest.raises(sfcd.db.exc.AuthError) as ex_info:
            manager.facebook.get_auth_token(None, '', '')
        assert str(ex_info.value) == 'empty email'

    def test__get_auth_token__email_too_long(
            self, manager, facebook_id):
        """
        get_auth_token: email too long error
        """
        with pytest.raises(sfcd.db.exc.AuthError) as ex_info:
            manager.facebook.get_auth_token('e' * 61, facebook_id, '')
        assert str(ex_info.value) == 'email too long'

    def test__get_auth_token__empty_facebook_id(
            self, manager, email, facebook_token):
        """
        get_auth_token: empty facebook_id error
        """
        with pytest.raises(sfcd.db.exc.AuthError) as ex_info:
            manager.facebook.get_auth_token(email, '', facebook_token)
        assert str(ex_info.value) == 'empty facebook_id'
        with pytest.raises(sfcd.db.exc.AuthError) as ex_info:
            manager.facebook.get_auth_token(email, None, facebook_token)
        assert str(ex_info.value) == 'empty facebook_id'

    def test__get_auth_token__facebook_id_too_long(
            self, manager, email):
        """
        get_auth_token: facebook_id too long error
        """
        with pytest.raises(sfcd.db.exc.AuthError) as ex_info:
            manager.facebook.get_auth_token(email, 'f' * 121, '')
        assert str(ex_info.value) == 'facebook_id too long'

    def test__get_auth_token__email_not_exists(
            self, session_scope, manager,
            email, facebook_id, facebook_token
    ):
        """
        get_auth_token: email not exists error
        """
        hashed, salt = sfcd.misc.crypto.Crypto.hash_passphrase(facebook_token)
        #
        with session_scope() as session:
            i = manager.simple._create_id_obj(email)
            session.add(i)
            session.flush()
            f = sfcd.db.sql.auth.facebook.Model(
                auth_id=i.id,
                facebook_id=facebook_id,
                hashed=hashed,
                salt=salt,
            )
            session.add(f)
        #
        with pytest.raises(sfcd.db.exc.AuthError) as ex_info:
            manager.facebook.get_auth_token(
                'invalid', facebook_id, '')
        assert str(ex_info.value) == \
            'email "invalid" not exists'

    def test__get_auth_token__facebook_id_not_exists(
            self, session_scope, manager,
            email, facebook_id, facebook_token
    ):
        """
        get_auth_token: facebook_id not exists error
        """
        hashed, salt = sfcd.misc.crypto.Crypto.hash_passphrase(facebook_token)
        #
        with session_scope() as session:
            i = manager.simple._create_id_obj(email)
            session.add(i)
            session.flush()
            f = sfcd.db.sql.auth.facebook.Model(
                auth_id=i.id,
                facebook_id=facebook_id,
                hashed=hashed,
                salt=salt,
            )
            session.add(f)
        #
        with pytest.raises(sfcd.db.exc.AuthError) as ex_info:
            manager.facebook.get_auth_token(email, 'invalid', '')
        assert str(ex_info.value) == \
            'facebook_id "invalid" not exists'

    def test__get_auth_token__invalid_passphrase(
            self, session_scope, manager,
            email, facebook_id, facebook_token
    ):
        """
        get_auth_token: invalid passphrase error
        """
        hashed, salt = sfcd.misc.crypto.Crypto.hash_passphrase(facebook_token)
        #
        with session_scope() as session:
            i = manager.simple._create_id_obj(email)
            session.add(i)
            session.flush()
            f = sfcd.db.sql.auth.facebook.Model(
                auth_id=i.id,
                facebook_id=facebook_id,
                hashed=hashed,
                salt=salt,
            )
            session.add(f)
        #
        with pytest.raises(sfcd.db.exc.AuthError) as ex_info:
            manager.facebook.get_auth_token(email, facebook_id, '')
        assert str(ex_info.value) == \
            'invalid passphrase'

    def test__get_auth_token(
            self, session_scope, manager,
            email, facebook_id, facebook_token
    ):
        """
        get_auth_token: OK
        """
        hashed, salt = sfcd.misc.crypto.Crypto.hash_passphrase(facebook_token)
        #
        with session_scope() as session:
            i = manager.simple._create_id_obj(email)
            session.add(i)
            session.flush()
            f = sfcd.db.sql.auth.facebook.Model(
                auth_id=i.id,
                facebook_id=facebook_id,
                hashed=hashed,
                salt=salt,
            )
            session.add(f)
        # some token
        token = manager.facebook.get_auth_token(
            email, facebook_id, facebook_token)
        assert len(token) == sfcd.misc.crypto.Crypto.auth_token_length
        assert token != sfcd.db.sql.auth.base.BaseMethod.AUTH_TOKEN_MOCK

    def test__get_auth_token__tokens_equal(
            self, session_scope, manager,
            email, facebook_id, facebook_token
    ):
        """
        record exists in db and passphrase check ok
        """
        hashed, salt = sfcd.misc.crypto.Crypto.hash_passphrase(facebook_token)
        #
        with session_scope() as session:
            i = manager.simple._create_id_obj(email)
            session.add(i)
            session.flush()
            f = sfcd.db.sql.auth.facebook.Model(
                auth_id=i.id,
                facebook_id=facebook_id,
                hashed=hashed,
                salt=salt,
            )
            session.add(f)
        # equal tokens
        token_1 = manager.facebook.get_auth_token(
            email, facebook_id, facebook_token)
        token_2 = manager.facebook.get_auth_token(
            email, facebook_id, facebook_token)
        assert len(token_1) == sfcd.misc.crypto.Crypto.auth_token_length
        assert token_1 == token_2


class TestManager:
    def test__processors(self, manager):
        """
        have properties for processors
        """
        assert isinstance(
            manager.simple,
            sfcd.db.sql.auth.simple.SimpleMethod
        )
        #
        assert isinstance(
            manager.facebook,
            sfcd.db.sql.auth.facebook.FacebookMethod
        )
