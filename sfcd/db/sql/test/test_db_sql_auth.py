import pytest

import sqlalchemy.sql
import sqlalchemy.sql.expression
import sqlalchemy.exc

import sfcd.misc
import sfcd.db.exc
import sfcd.db.sql.auth


########################################
# fixtures
########################################

@pytest.fixture(scope='session')
def auth_manager(session_maker):
    return sfcd.db.sql.auth.AuthManager(session_maker)


########################################
# models tests
########################################

class TestModels:
    def test__id(self, session, email, auth_token):
        """
        test auth creation
        """
        i = sfcd.db.sql.auth.ID(
            email=email,
            auth_token=auth_token,
        )
        session.add(i)
        session.commit()
        i = session.query(sfcd.db.sql.auth.ID).filter_by(id=i.id).first()
        assert i.id is not None
        assert i.email == email
        assert i.auth_token == auth_token

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
        hashed, salt = sfcd.misc.Crypto.hash_passphrase(password)
        #
        i = sfcd.db.sql.auth.ID(email=email)
        session.add(i)
        session.flush()
        p = sfcd.db.sql.auth.Simple(auth_id=i.id, hashed=hashed, salt=salt)
        session.add(p)
        session.commit()
        p = session.query(sfcd.db.sql.auth.Simple).join(
            sfcd.db.sql.auth.ID).filter(
                sfcd.db.sql.auth.ID.email == email).one()
        assert p.hashed == hashed
        assert p.salt == salt

    def test__rollback(self, session, email, password):
        """
        test rollback for auth records
        """
        hashed, salt = sfcd.misc.Crypto.hash_passphrase(password)
        #
        i = sfcd.db.sql.auth.ID(email=email)
        session.add(i)
        session.flush()
        p = sfcd.db.sql.auth.Simple(auth_id=i.id, hashed=hashed, salt=salt)
        session.add(p)
        session.flush()
        session.rollback()
        assert not session.query(sqlalchemy.sql.exists().where(
            sfcd.db.sql.auth.ID.email == email)).scalar()
        assert not session.query(sqlalchemy.sql.exists().where(
            sfcd.db.sql.auth.Simple.hashed == hashed)).scalar()

    def test__simple__same_id(self, session, email, password):
        """
        test simple auth creation with same auth.id
        """
        hashed, salt = sfcd.misc.Crypto.hash_passphrase(password)
        #
        i = sfcd.db.sql.auth.ID(email=email)
        session.add(i)
        session.flush()
        p_1 = sfcd.db.sql.auth.Simple(auth_id=i.id, hashed=hashed, salt=salt)
        p_2 = sfcd.db.sql.auth.Simple(auth_id=i.id, hashed=hashed, salt=salt)
        session.add_all([p_1, p_2])
        with pytest.raises(sqlalchemy.exc.IntegrityError):
            session.commit()

    def test__facebook(self, session, email, facebook_id, facebook_token):
        """
        test facebook auth creation
        """
        hashed, salt = sfcd.misc.Crypto.hash_passphrase(facebook_token)
        #
        i = sfcd.db.sql.auth.ID(email=email)
        session.add(i)
        session.flush()
        f = sfcd.db.sql.auth.Facebook(
            auth_id=i.id,
            facebook_id=facebook_id,
            hashed=hashed,
            salt=salt,
        )
        session.add(f)
        session.commit()
        f = session.query(sfcd.db.sql.auth.Facebook).join(
            sfcd.db.sql.auth.ID).filter(
                sfcd.db.sql.auth.ID.email == email).one()
        assert f.facebook_id == facebook_id
        assert f.hashed == hashed
        assert f.salt == salt

    def test__facebook__same_id(
            self, session, email, facebook_id, facebook_id_2, facebook_token
    ):
        """
        test facebook auth creation with same auth.id
        """
        hashed, salt = sfcd.misc.Crypto.hash_passphrase(facebook_token)
        #
        i = sfcd.db.sql.auth.ID(email=email)
        session.add(i)
        session.flush()
        f_1 = sfcd.db.sql.auth.Facebook(
            auth_id=i.id,
            facebook_id=facebook_id,
            hashed=hashed,
            salt=salt,
        )
        f_2 = sfcd.db.sql.auth.Facebook(
            auth_id=i.id,
            facebook_id=facebook_id_2,
            hashed=hashed,
            salt=salt,
        )
        session.add_all([f_1, f_2])
        with pytest.raises(sqlalchemy.exc.IntegrityError):
            session.commit()

    def test__facebook__same_facebook_id(
            self, session, email, email_2, facebook_id, facebook_token
    ):
        """
        test facebook auth creation with same facebook_id
        """
        hashed, salt = sfcd.misc.Crypto.hash_passphrase(facebook_token)
        #
        i_1 = sfcd.db.sql.auth.ID(email=email)
        i_2 = sfcd.db.sql.auth.ID(email=email_2)
        session.add_all([i_1, i_2])
        session.flush()
        f_1 = sfcd.db.sql.auth.Facebook(
            auth_id=i_1.id,
            facebook_id=facebook_id,
            hashed=hashed,
            salt=salt,
        )
        f_2 = sfcd.db.sql.auth.Facebook(
            auth_id=i_2.id,
            facebook_id=facebook_id,
            hashed=hashed,
            salt=salt,
        )
        session.add_all([f_1, f_2])
        with pytest.raises(sqlalchemy.exc.IntegrityError):
            session.commit()


########################################
# manager tests
########################################

class TestManager:
    def test__register_simple_auth(
            self, session, auth_manager, email, password
    ):
        """
        add simple auth and check result
        """
        auth_manager.register_simple_auth(email, password)
        #
        obj = session.query(
            sfcd.db.sql.auth.Simple).join(sfcd.db.sql.auth.ID).filter(
                sqlalchemy.sql.expression.and_(
                    sfcd.db.sql.auth.ID.email == email,
                )
            ).first()
        assert obj
        assert sfcd.misc.Crypto.validate_passphrase(
            password, obj.hashed, obj.salt)

    def test__register_simple_auth__empty_email(self, auth_manager, password):
        """
        add simple auth with empty email
        """
        with pytest.raises(sfcd.db.exc.AuthError) as ex_info:
            auth_manager.register_simple_auth('', password)
        assert str(ex_info.value) == 'empty email'
        with pytest.raises(sfcd.db.exc.AuthError) as ex_info:
            auth_manager.register_simple_auth(None, password)
        assert str(ex_info.value) == 'empty email'

    def test__register_simple_auth__email_too_long(self, auth_manager):
        """
        register simple auth: email too long error
        """
        with pytest.raises(sfcd.db.exc.AuthError) as ex_info:
            auth_manager.register_simple_auth('e' * 61, '')
        assert str(ex_info.value) == 'email too long'

    def test__register_simple_auth__email_exists(
            self, session, auth_manager,
            email, password
    ):
        """
        catch exception on existent email
        """
        hashed, salt = sfcd.misc.Crypto.hash_passphrase(password)
        #
        i = sfcd.db.sql.auth.ID(email=email)
        session.add(i)
        session.flush()
        p = sfcd.db.sql.auth.Simple(auth_id=i.id, hashed=hashed, salt=salt)
        session.add(p)
        session.commit()
        #
        with pytest.raises(sfcd.db.exc.AuthError) as ex_info:
            auth_manager.register_simple_auth(email, password)
        assert str(ex_info.value) == \
            'email "{}" exists'.format(email)

    def test__get_token_simple_auth(
            self, session, auth_manager, email, password
    ):
        """
        test if simple auth exists
        """
        hashed, salt = sfcd.misc.Crypto.hash_passphrase(password)
        #
        i = auth_manager._create_id_obj(session, email)
        session.add(i)
        session.flush()
        p = sfcd.db.sql.auth.Simple(auth_id=i.id, hashed=hashed, salt=salt)
        session.add(p)
        session.commit()
        # some token
        token = auth_manager.get_token_simple_auth(email, password)
        assert len(token) == sfcd.misc.Crypto.auth_token_length
        assert token != auth_manager.AUTH_TOKEN_MOCK

    def test__get_token_simple_auth__tokens_equal(
            self, session, auth_manager, email, password
    ):
        """
        test if simple auth exists
        """
        hashed, salt = sfcd.misc.Crypto.hash_passphrase(password)
        #
        i = auth_manager._create_id_obj(session, email)
        session.add(i)
        session.flush()
        p = sfcd.db.sql.auth.Simple(auth_id=i.id, hashed=hashed, salt=salt)
        session.add(p)
        session.commit()
        # check equal
        token_1 = auth_manager.get_token_simple_auth(email, password)
        token_2 = auth_manager.get_token_simple_auth(email, password)
        assert len(token_1) == sfcd.misc.Crypto.auth_token_length
        assert token_1 == token_2

    def test__get_token_simple_auth__not_exists(
            self, session, auth_manager, email, password):
        """
        test if simple auth not exists
        """
        hashed, salt = sfcd.misc.Crypto.hash_passphrase(password)
        #
        i = auth_manager._create_id_obj(session, email)
        session.add(i)
        session.flush()
        p = sfcd.db.sql.auth.Simple(auth_id=i.id, hashed=hashed, salt=salt)
        session.add(p)
        session.commit()
        #
        with pytest.raises(sfcd.db.exc.AuthError) as ex_info:
            auth_manager.get_token_simple_auth('', password)
        assert str(ex_info.value) == \
            'empty email'
        with pytest.raises(sfcd.db.exc.AuthError) as ex_info:
            auth_manager.get_token_simple_auth('exists@me.me', password)
        assert str(ex_info.value) == \
            'email "exists@me.me" not exists'
        with pytest.raises(sfcd.db.exc.AuthError) as ex_info:
            auth_manager.get_token_simple_auth(email, '')
        assert str(ex_info.value) == \
            'invalid password'

    def test__register_facebook_auth(
            self, session, auth_manager, email, facebook_id, facebook_token):
        """
        add facebook auth and check result
        """
        auth_manager.register_facebook_auth(email, facebook_id, facebook_token)
        #
        obj = session.query(
            sfcd.db.sql.auth.Facebook).join(sfcd.db.sql.auth.ID).filter(
                sqlalchemy.sql.expression.and_(
                    sfcd.db.sql.auth.ID.email == email,
                    sfcd.db.sql.auth.Facebook.facebook_id == facebook_id,
                )
            ).first()
        assert obj
        assert sfcd.misc.Crypto.validate_passphrase(
            facebook_token, obj.hashed, obj.salt)

    def test__register_facebook_auth__empty_email(
            self, auth_manager):
        """
        catch error on empty facebook_id
        """
        with pytest.raises(sfcd.db.exc.AuthError) as ex_info:
            auth_manager.register_facebook_auth('', '', '')
        assert str(ex_info.value) == 'empty email'
        with pytest.raises(sfcd.db.exc.AuthError) as ex_info:
            auth_manager.register_facebook_auth(None, '', '')
        assert str(ex_info.value) == 'empty email'

    def test__register_facebook_auth__email_too_long(
            self, auth_manager, facebook_id):
        """
        register facebook auth: email too long
        """
        with pytest.raises(sfcd.db.exc.AuthError) as ex_info:
            auth_manager.register_facebook_auth('e' * 61, facebook_id, '')
        assert str(ex_info.value) == 'email too long'

    def test__register_facebook_auth__empty_facebook_id(
            self, auth_manager, email, facebook_token):
        """
        catch error on empty facebook_id
        """
        with pytest.raises(sfcd.db.exc.AuthError) as ex_info:
            auth_manager.register_facebook_auth(email, '', facebook_token)
        assert str(ex_info.value) == 'empty facebook_id'
        with pytest.raises(sfcd.db.exc.AuthError) as ex_info:
            auth_manager.register_facebook_auth(email, None, facebook_token)
        assert str(ex_info.value) == 'empty facebook_id'

    def test__register_facebook_auth__facebook_id_too_long(
            self, auth_manager, email):
        """
        register facebook auth: facebook_id too long
        """
        with pytest.raises(sfcd.db.exc.AuthError) as ex_info:
            auth_manager.register_facebook_auth(email, 'f' * 121, '')
        assert str(ex_info.value) == 'facebook_id too long'

    def test__register_facebook_auth__email_exists(
            self, session, auth_manager,
            email, facebook_id, facebook_token
    ):
        """
        catch exception on existent email
        """
        hashed, salt = sfcd.misc.Crypto.hash_passphrase(facebook_token)
        #
        i = auth_manager._create_id_obj(session, email)
        session.add(i)
        session.flush()
        f = sfcd.db.sql.auth.Facebook(
            auth_id=i.id,
            facebook_id=facebook_id,
            hashed=hashed,
            salt=salt,
        )
        session.add(f)
        session.commit()
        #
        with pytest.raises(sfcd.db.exc.AuthError) as ex_info:
            auth_manager.register_facebook_auth(
                email, facebook_id, facebook_token)
        assert str(ex_info.value) == \
            'email "{}" exists'.format(email)

    def test__register_facebook_auth__facebook_id_exists(
            self, session, auth_manager,
            email, email_2, facebook_id, facebook_token
    ):
        """
        catch exception on existent facebook_id
        """
        hashed, salt = sfcd.misc.Crypto.hash_passphrase(facebook_token)
        #
        i = auth_manager._create_id_obj(session, email)
        session.add(i)
        session.flush()
        f = sfcd.db.sql.auth.Facebook(
            auth_id=i.id,
            facebook_id=facebook_id,
            hashed=hashed,
            salt=salt,
        )
        session.add(f)
        session.commit()
        #
        with pytest.raises(sfcd.db.exc.AuthError) as ex_info:
            auth_manager.register_facebook_auth(
                email_2, facebook_id, facebook_token)
        assert str(ex_info.value) == \
            'facebook_id "{}" exists'.format(facebook_id)

    def test__get_token_facebook_auth(
            self, session, auth_manager, email, facebook_id, facebook_token):
        """
        record exists in db and passphrase check ok
        """
        hashed, salt = sfcd.misc.Crypto.hash_passphrase(facebook_token)
        #
        i = auth_manager._create_id_obj(session, email)
        session.add(i)
        session.flush()
        f = sfcd.db.sql.auth.Facebook(
            auth_id=i.id,
            facebook_id=facebook_id,
            hashed=hashed,
            salt=salt,
        )
        session.add(f)
        session.commit()
        # some token
        token = auth_manager.get_token_facebook_auth(
            email, facebook_id, facebook_token)
        assert len(token) == sfcd.misc.Crypto.auth_token_length
        assert token != auth_manager.AUTH_TOKEN_MOCK

    def test__get_token_facebook_auth__tokens_equal(
            self, session, auth_manager, email, facebook_id, facebook_token):
        """
        record exists in db and passphrase check ok
        """
        hashed, salt = sfcd.misc.Crypto.hash_passphrase(facebook_token)
        #
        i = auth_manager._create_id_obj(session, email)
        session.add(i)
        session.flush()
        f = sfcd.db.sql.auth.Facebook(
            auth_id=i.id,
            facebook_id=facebook_id,
            hashed=hashed,
            salt=salt,
        )
        session.add(f)
        session.commit()
        # equal tokens
        token_1 = auth_manager.get_token_facebook_auth(
            email, facebook_id, facebook_token)
        token_2 = auth_manager.get_token_facebook_auth(
            email, facebook_id, facebook_token)
        assert len(token_1) == sfcd.misc.Crypto.auth_token_length
        assert token_1 == token_2

    def test__get_token_facebook_auth__not_exists(
            self, session, auth_manager, email, facebook_id, facebook_token):
        """
        record not exists in db
        """
        hashed, salt = sfcd.misc.Crypto.hash_passphrase(facebook_token)
        #
        i = auth_manager._create_id_obj(session, email)
        session.add(i)
        session.flush()
        f = sfcd.db.sql.auth.Facebook(
            auth_id=i.id,
            facebook_id=facebook_id,
            hashed=hashed,
            salt=salt,
        )
        session.add(f)
        session.commit()
        #
        with pytest.raises(sfcd.db.exc.AuthError) as ex_info:
            auth_manager.get_token_facebook_auth('', '', '')
        assert str(ex_info.value) == \
            'empty email'
        with pytest.raises(sfcd.db.exc.AuthError) as ex_info:
            auth_manager.get_token_facebook_auth(
                'exists@me.me', facebook_id, '')
        assert str(ex_info.value) == \
            'email "exists@me.me" not exists'
        with pytest.raises(sfcd.db.exc.AuthError) as ex_info:
            auth_manager.get_token_facebook_auth(email, '', '')
        assert str(ex_info.value) == \
            'empty facebook_id'
        with pytest.raises(sfcd.db.exc.AuthError) as ex_info:
            auth_manager.get_token_facebook_auth(email, 'exists', '')
        assert str(ex_info.value) == \
            'facebook_id "exists" not exists'
        with pytest.raises(sfcd.db.exc.AuthError) as ex_info:
            auth_manager.get_token_facebook_auth(email, facebook_id, '')
        assert str(ex_info.value) == \
            'invalid passphrase'
