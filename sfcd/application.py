import logging
import logging.handlers

import flask

import sfcd.db.sql.engine
import sfcd.logic.controller
import sfcd.views.registry
import sfcd.config


class Application(object):
    """
    System initialization methods
    """

    @classmethod
    def setup_application(cls, db_type, db_url):
        """
        - Initialize database engine
          based on config settings
        - Initialize logic controller
        - Initialize flask app and register views
        - Set @app.before_request and @app.after_request
          send controller to each request via flask.g
        - Setup logging

        return :flask_app:, :db_engine:
        use :db_engine: only for test needs
        """
        # database engine
        if db_type == 'sql':
            db_engine = sfcd.db.sql.engine.DBEngine(db_url)
        elif db_type == 'mongo':
            # db_engine = sfcd.db.mongo.DBEngine(db_url)
            pass

        # logic controller
        controller = sfcd.logic.controller.Controller(db_engine)

        # flask app
        flask_app = flask.Flask('sfcd')
        sfcd.views.registry.register_views(flask_app)

        # globals
        sfcd.views.registry.register_flask_before_request(
            flask_app, controller)

        # logging
        cls.setup_logging(flask_app)

        # return db_engine only for test needs
        return flask_app, db_engine

    @staticmethod
    def _logging_file_handler(filename, logging_level):
        """
        Get time rotating file handler for logger redirection
        Rotate every midnight
        """
        fh = logging.handlers.TimedRotatingFileHandler(
            filename=filename,
            when='midnight',
            interval=1,
        )
        fh.setLevel(logging_level)
        formatter = logging.Formatter(
            '[%(asctime)s] %(levelname)s [%(name)s] %(message)s'
        )
        fh.setFormatter(formatter)
        return fh

    @classmethod
    def _setup_logger(cls, log_name, filename, logging_level):
        """
        Write specified messages for log class :log_name:
        to file :filename: with :logging_level:
        """
        fh = cls._logging_file_handler(filename, logging_level)
        log = logging.getLogger(log_name)
        log.setLevel(logging_level)
        log.addHandler(fh)

    @classmethod
    def setup_logging(cls, flask_app):
        """
        Setup components logs
        """
        # sql log: sqlalchemy
        cls._setup_logger(
            'sqlalchemy',
            sfcd.config.LOG_FILENAME__SQL,
            sfcd.config.LOG_LEVEL,
        )
        # flask log
        flask_app.logger.addHandler(cls._logging_file_handler(
            sfcd.config.LOG_FILENAME__SYSTEM,
            sfcd.config.LOG_LEVEL,
        ))
        flask_app.logger.setLevel(sfcd.config.LOG_LEVEL)
        # view log: werkzeug
        cls._setup_logger(
            'werkzeug',
            sfcd.config.LOG_FILENAME__SYSTEM,
            sfcd.config.LOG_LEVEL,
        )
        # view log: view
        cls._setup_logger(
            'view',
            sfcd.config.LOG_FILENAME__VIEW,
            sfcd.config.LOG_LEVEL,
        )
        # app log: sfcd
        cls._setup_logger(
            'sfcd',
            sfcd.config.LOG_FILENAME__APP,
            sfcd.config.LOG_LEVEL,
        )
