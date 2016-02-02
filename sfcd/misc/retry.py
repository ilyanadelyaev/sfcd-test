import functools


def retry(exc_cls, tries=3, logger=None):
    """
    Retry decorator
    :exc_cls: class to follow
    :tries: number of tries
    """
    def decoy(f):
        @functools.wraps(f)
        def functor(*args, **kwargs):
            t = tries  # copy
            # last one without catching
            while t > 1:
                try:
                    return f(*args, **kwargs)
                except exc_cls as ex:
                    if logger:
                        msg = 'Retry for "{}" / attempts: {}'.format(
                            f.__name__, (t - 1))
                        logger.error(msg)
                        logger.exception(ex)
                    t -= 1
            return f(*args, **kwargs)
        return functor
    return decoy
