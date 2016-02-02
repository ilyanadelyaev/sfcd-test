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


def register_flask_before_request(flask_app, controller):
    """
    Register here all specific methods per-request call
    """

    @flask_app.before_request
    def before_request():
        flask.g.controller = controller
        #
        flask.g.request_id = str(uuid.uuid4())
        #
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
    def after_request(resp):
        message = '[{}] ({})'.format(
            flask.g.request_id,
            resp.status_code,
        )
        if resp.mimetype == 'application/json':
            message += ' {}'.format(resp.data.replace('\n', ''))
        logger.info(message)
        return resp
