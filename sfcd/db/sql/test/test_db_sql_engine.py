import pytest


class TestDBEngine:
    @staticmethod
    def _check_attribute_exists(obj, var_name):
        return (
            hasattr(obj, var_name) and
            not callable(getattr(obj, var_name))
        )

    @staticmethod
    def _check_method_exists(obj, method_name):
        return (
            hasattr(obj, method_name) and
            callable(getattr(obj, method_name))
        )

    def test__auth_manager_methods(self, db_engine):
        assert self._check_attribute_exists(
            db_engine.__class__, 'auth')
        #
        assert self._check_method_exists(
            db_engine.auth.__class__, 'register_simple_auth')
        assert self._check_method_exists(
            db_engine.auth.__class__, 'get_token_simple_auth')
        assert self._check_method_exists(
            db_engine.auth.__class__, 'register_facebook_auth')
        assert self._check_method_exists(
            db_engine.auth.__class__, 'get_token_facebook_auth')
