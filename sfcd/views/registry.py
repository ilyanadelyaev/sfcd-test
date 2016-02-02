import uuid
import logging

import flask

from . import auth


logger = logging.getLogger('view')


def register_views(flask_app):
    """
    views register magic
    """
    for v in (auth, ):
        v.register_view(flask_app)


def register_flask_before_request(config, flask_app, controller):
    """
    Register here all specific methods per-request call
    """

    @flask_app.before_request
    def request_id_to_g():
        flask.g.request_id = str(uuid.uuid4())

    @flask_app.before_request
    def system_to_g():
        flask.g.config = config
        flask.g.controller = controller

    @flask_app.before_request
    def log_pre_request():
        request = flask.request
        message = '[{}] {} -> ({} {})'.format(
            flask.g.request_id,
            request.remote_addr,
            request.path, request.method,
        )
        if request.mimetype == 'application/json':
            message += ' {}'.format(request.data)
        logger.info(message)

    @flask_app.after_request
    def log_post_request(resp):
        message = '[{}] ({})'.format(
            flask.g.request_id,
            resp.status_code,
        )
        if resp.mimetype == 'application/json':
            message += ' {}'.format(resp.data.replace('\n', ''))
        logger.info(message)
        return resp
