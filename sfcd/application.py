import os
import logging
import logging.handlers

import flask

import sfcd.db.common
import sfcd.logic.controller
import sfcd.views.registry


class Application(object):
    """
    System initialization methods
    """

    @classmethod
    def setup_application(cls, config):
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
        db_engine = sfcd.db.common.get_db_engine(config)

        # logic controller
        controller = sfcd.logic.controller.Controller(
            config, db_engine)

        # flask app
        flask_app = flask.Flask('sfcd')
        sfcd.views.registry.register_views(flask_app)

        # globals
        sfcd.views.registry.register_flask_before_request(
            flask_app, controller)

        # logging
        cls._setup_logging(config, flask_app)

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
    def _setup_logging(cls, config, flask_app):
        """
        Setup components logs
        """
        # ensure dirs
        if not os.path.exists(config.system.logger.path):
            os.makedirs(config.system.logger.path)

        # sql log: sqlalchemy
        cls._setup_logger(
            'sqlalchemy',
            os.path.join(
                config.system.logger.path,
                config.system.logger.sql
            ),
            config.system.logger.level,
        )
        # flask log
        flask_app.logger.addHandler(cls._logging_file_handler(
            os.path.join(
                config.system.logger.path,
                config.system.logger.system
            ),
            config.system.logger.level,
        ))
        flask_app.logger.setLevel(config.system.logger.level)
        # view log: werkzeug
        cls._setup_logger(
            'werkzeug',
            os.path.join(
                config.system.logger.path,
                config.system.logger.system
            ),
            config.system.logger.level,
        )
        # view log: view
        cls._setup_logger(
            'view',
            os.path.join(
                config.system.logger.path,
                config.system.logger.view
            ),
            config.system.logger.level,
        )
        # app log: sfcd
        cls._setup_logger(
            'sfcd',
            os.path.join(
                config.system.logger.path,
                config.system.logger.app
            ),
            config.system.logger.level,
        )
