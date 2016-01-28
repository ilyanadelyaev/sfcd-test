import logging
import logging.handlers

import flask

import sfcd.db.sql
import sfcd.logic
import sfcd.views
import sfcd.config


application = None


class Application(object):
    """
    global application store intercomponent objects
    all this magic needs for tests
    to link web-view and logic
    setup logging for components
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

        # logging
        self.setup_logging()

    def setup_logging(self):
        # system log
        self.log = self._setup_log(
            'sfcd:system',
            sfcd.config.LOG_FILENAME__SYSTEM,
            sfcd.config.LOG_LEVEL,
        )
        # sql log
        self._setup_log(
            'sqlalchemy',
            sfcd.config.LOG_FILENAME__SQL,
            sfcd.config.LOG_LEVEL,
        )
        # flask log
        self._setup_log(
            'werkzeug',
            sfcd.config.LOG_FILENAME__VIEW,
            sfcd.config.LOG_LEVEL,
        )
        web_view_log_handler = self._log_file_handler(
            sfcd.config.LOG_FILENAME__VIEW,
            sfcd.config.LOG_LEVEL,
        )
        self.web_view.logger.addHandler(web_view_log_handler)
        self.web_view.logger.setLevel(sfcd.config.LOG_LEVEL)

    @staticmethod
    def _log_file_handler(filename, logging_level):
        fh = logging.handlers.TimedRotatingFileHandler(
            filename=filename,
            when='midnight',
            interval=1,
        )
        fh.setLevel(logging_level)
        formatter = logging.Formatter(
            '[%(asctime)s] %(levelname)s [%(name)s:%(lineno)s] %(message)s'
        )
        fh.setFormatter(formatter)
        return fh

    @classmethod
    def _setup_log(cls, log_name, filename, logging_level):
        fh = cls._log_file_handler(filename, logging_level)
        #
        log = logging.getLogger(log_name)
        log.setLevel(logging_level)
        log.addHandler(fh)
        #
        return log
