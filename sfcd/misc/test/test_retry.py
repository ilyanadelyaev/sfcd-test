import pytest

import sfcd.misc.retry


class TestRetry:
    def test__no_retry(self):
        @sfcd.misc.retry.retry(Exception, 2)
        def f(v):
            v[0] -= 1
        #
        value = [2]
        f(value)
        # one call without retries
        assert value[0] == 1

    def test__exception_not_match(self):
        @sfcd.misc.retry.retry(AttributeError, 2)
        def f(v):
            v[0] -= 1
            raise RuntimeError
        #
        with pytest.raises(RuntimeError):
            value = [3]
            f(value)
        # one call without retries
        assert value[0] == 2

    def test__0_attempts(self):
        @sfcd.misc.retry.retry(Exception, 0)
        def f(v):
            v[0] -= 1
            raise Exception
        #
        with pytest.raises(Exception):
            value = [1]
            f(value)
        # one call - ignore zero
        assert value[0] == 0

    def test__1_attempt(self):
        @sfcd.misc.retry.retry(Exception, 1)
        def f(v):
            v[0] -= 1
            raise Exception
        #
        with pytest.raises(Exception):
            value = [1]
            f(value)
        # one call
        assert value[0] == 0

    def test__2_attempts(self):
        @sfcd.misc.retry.retry(Exception, 2)
        def f(v):
            v[0] -= 1
            raise Exception
        #
        with pytest.raises(Exception):
            value = [2]
            f(value)
        # two calls
        assert value[0] == 0

    def test__default_attempts(self):
        @sfcd.misc.retry.retry(Exception)
        def f(v):
            v[0] -= 1
            raise Exception
        #
        with pytest.raises(Exception):
            value = [3]
            f(value)
        # three calls
        assert value[0] == 0
