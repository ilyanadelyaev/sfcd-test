import json

import flask

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
    request_data = json.loads(request.data)

    resp_data = {}
    resp_code = 400

    try:
        # call logic.auth.signup via logic.controller
        sfcd.application.controller.auth.signup(request_data)
        resp_data = {'status': 'signup'}
        resp_code = 200
    except sfcd.logic.auth.AuthError as ex:
        resp_data = {'error': str(ex)}
    except Exception as ex:
        resp_data = {'error': str(ex)}

    return flask.jsonify(resp_data), resp_code


@blueprint.route('/auth/signin/', methods=['POST'])
def auth_signin():
    """
    POST json request handler
    check user auth in system
    """
    request = flask.request  # hack
    request_data = json.loads(request.data)

    resp_data = {}
    resp_code = 400

    try:
        # call logic.auth.signin via logic.controller
        sfcd.application.controller.auth.signin(request_data)
        resp_data = {'status': 'signin'}
        resp_code = 200
    except sfcd.logic.auth.AuthError as ex:
        resp_data = {'error': str(ex)}
    except Exception as ex:
        resp_data = {'error': str(ex)}

    return flask.jsonify(resp_data), resp_code
