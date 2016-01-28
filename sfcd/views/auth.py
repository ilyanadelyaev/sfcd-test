import uuid
import json

import flask

import sfcd
import sfcd.config
import sfcd.logic


blueprint = flask.Blueprint('auth', __name__)


def register_view(web_view):
    """
    some view register magic
    """
    web_view.register_blueprint(blueprint)


@blueprint.route('/auth/signup/', methods=['POST'])
def auth_signup():
    """
    POST json request handler
    register user in system
    """
    request = flask.request  # hack

    request_id = str(uuid.uuid4())
    request_data = json.loads(request.data)

    sfcd.application.web_view.logger.info(
        '[%s] %s -> %s %s %s',
        request_id,
        request.remote_addr,
        request.path, request.method,
        request_data,
    )

    resp_data = {}
    resp_code = 200

    try:
        # call logic.auth.signup via logic.controller
        sfcd.application.controller.auth.signup(request_data)
    except sfcd.logic.auth.AuthError as ex:
        sfcd.application.web_view.logger.exception(ex)
        resp_data = {'error': str(ex)}
        resp_code = 400
    except Exception as ex:
        sfcd.application.web_view.logger.exception(ex)
        resp_data = {'error': 'Internal error'}
        resp_code = 400

    sfcd.application.web_view.logger.info(
        '[%s] (%s) %s',
        request_id,
        resp_code, resp_data,
    )

    return flask.jsonify(resp_data), resp_code


@blueprint.route('/auth/signin/', methods=['POST'])
def auth_signin():
    """
    POST json request handler
    check user auth in system
    """
    request = flask.request  # hack

    request_id = str(uuid.uuid4())
    request_data = json.loads(request.data)

    sfcd.application.web_view.logger.info(
        '[%s] %s -> %s %s %s',
        request_id,
        request.remote_addr,
        request.path, request.method,
        request_data,
    )

    resp_data = {}
    resp_code = 200

    try:
        # call logic.auth.signin via logic.controller
        sfcd.application.controller.auth.signin(request_data)
    except sfcd.logic.auth.AuthError as ex:
        sfcd.application.web_view.logger.exception(ex)
        resp_data = {'error': str(ex)}
        resp_code = 400
    except Exception as ex:
        sfcd.application.web_view.logger.exception(ex)
        resp_data = {'error': 'Internal error'}
        resp_code = 400

    sfcd.application.web_view.logger.info(
        '[%s] (%s) %s',
        request_id,
        resp_code, resp_data,
    )

    return flask.jsonify(resp_data), resp_code
