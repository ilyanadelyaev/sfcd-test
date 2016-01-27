import flask

import sfcd.db.sql
import sfcd.logic
import sfcd.views


application = None


class Application(object):
    """
    global application store intercomponent objects
    all this magic needs for tests
    to link web-view and logic
    """
    def __init__(self, db_type, db_url):
        # db engine
        self.db_engine = None
        if db_type == 'sql':
            self.db_engine = sfcd.db.sql.DBEngine(db_url)
        elif db_type == 'mongo':
            # self.db_engine = sfcd.db.mongo.DBEngine(db_url)
            pass

        # controller
        self.controller = sfcd.logic.Controller(self.db_engine)

        # view
        self.web_view = flask.Flask(__name__)
        sfcd.views.register_views(self.web_view)
