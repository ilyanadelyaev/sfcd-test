import pytest


class TestDBEngine:
    def test__auth_manager_methods(self, db_engine):
        assert hasattr(db_engine, 'auth')
