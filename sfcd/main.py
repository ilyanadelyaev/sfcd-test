import argparse
import logging

import sfcd.application
import sfcd.config


logger = logging.getLogger('sfcd')


if __name__ == '__main__':
    # command line arguments parser
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--config',
        required=True,
        help='path to application config',
    )
    args = parser.parse_args()

    # create system config
    config = sfcd.config.Config(args.config)

    # second param for tests so skip it
    flask_app, _ = \
        sfcd.application.Application.setup_application(config)

    # after Application.setup_application
    logger.info('Initialized')
    logger.info('Config: "{}"'.format(config))

    # run web-view
    flask_app.run(
        host=config.system.flask.host,
        port=config.system.flask.port,
        debug=int(config.system.flask.debug),
    )

    logger.info('Terminate')
