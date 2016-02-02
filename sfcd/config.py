import configure


class Config(object):
    def __init__(self, file_name):
        self.__config = configure.Configuration.from_file(
            file_name).configure()

    def __str__(self):
        return str(self.__config)

    def __getattr__(self, attr):
        if not hasattr(self.__config, attr):
            raise AttributeError(
                "{} instance has no attribute '{}'".format(
                    self.__config.__class__.__name__, attr))
        return getattr(self.__config, attr)
