import sfcd.db.sql
import sfcd.db.sql.auth


class DBEngine(object):
    """
    Hides dababase realisation from logic layer
    Holds db_connection and all managers in one place
    #
    SQL-Alchemy inside
    """

    def __init__(self, engine_url):
        self.session_maker = sfcd.db.sql.init_engine(engine_url=engine_url)
        # managers
        self.auth_manager = sfcd.db.sql.auth.AuthManager(self.session_maker)

    @property
    def auth(self):
        """
        auth manager shortcut
        """
        return self.auth_manager
