import json
import logging

import flask

import sfcd.config
import sfcd.logic


logger = logging.getLogger('view')


blueprint = flask.Blueprint('auth', __name__, url_prefix='/auth')


def register_view(flask_app):
    """
    some view register magic
    """
    flask_app.register_blueprint(blueprint)


@blueprint.route('/signup/', methods=['POST'])
def auth_signup():
    """
    POST json request handler
    register user in system
    """
    request = flask.request
    request_data = json.loads(request.data)

    resp_data = {}
    resp_code = 200

    try:
        # call logic.auth.signup via logic.controller
        flask.g.controller.auth.signup(request_data)
    except sfcd.logic.auth.AuthError as ex:
        logger.exception(ex)
        resp_data = {'error': str(ex)}
        resp_code = 400
    except Exception as ex:
        logger.exception(ex)
        resp_data = {'error': 'Internal error'}
        resp_code = 400

    return flask.jsonify(resp_data), resp_code


@blueprint.route('/signin/', methods=['POST'])
def auth_signin():
    """
    POST json request handler
    check user auth in system
    """
    request = flask.request
    request_data = json.loads(request.data)

    resp_data = {}
    resp_code = 200

    try:
        # call logic.auth.signin via logic.controller
        flask.g.controller.auth.signin(request_data)
    except sfcd.logic.auth.AuthError as ex:
        logger.exception(ex)
        resp_data = {'error': str(ex)}
        resp_code = 400
    except Exception as ex:
        logger.exception(ex)
        resp_data = {'error': 'Internal error'}
        resp_code = 400

    return flask.jsonify(resp_data), resp_code
