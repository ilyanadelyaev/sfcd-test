import logging

import flask

import sfcd.logic.exc


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
    resp_data = {}
    resp_code = 200

    try:
        # call logic.auth.signup via logic.controller
        flask.g.controller.auth.signup(
            flask.g.config,
            flask.request.json,
        )
    except sfcd.logic.exc.LogicError as ex:
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
    resp_data = {}
    resp_code = 200

    try:
        # call logic.auth.signin via logic.controller
        token = flask.g.controller.auth.signin(
            flask.g.config,
            flask.request.json,
        )
        resp_data = {'auth_token': token}
    except sfcd.logic.exc.LogicError as ex:
        logger.exception(ex)
        resp_data = {'error': str(ex)}
        resp_code = 400
    except Exception as ex:
        logger.exception(ex)
        resp_data = {'error': 'Internal error'}
        resp_code = 400

    return flask.jsonify(resp_data), resp_code
