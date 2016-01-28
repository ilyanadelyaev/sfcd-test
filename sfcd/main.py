import logging

import sfcd.application
import sfcd.config


logger = logging.getLogger('sfcd')


if __name__ == '__main__':
    # get db params from config
    db_type = sfcd.config.DB_TYPE
    db_url = None
    if sfcd.config.DB_TYPE == 'sql':
        db_url = sfcd.config.SQL_DB_URL
    elif sfcd.config.DB_TYPE == 'mongo':
        db_url = sfcd.config.MONGO_DB_URL

    flask_app, _ = \
        sfcd.application.Application.setup_application(db_type, db_url)

    # after Application.setup_application
    logger.info('Initialized')
    logger.info('DB config: {} : {}'.format(db_url, db_url))

    # run web-view
    flask_app.run(
        host=sfcd.config.FLASK_HOST,
        port=sfcd.config.FLASK_PORT,
        debug=sfcd.config.FLASK_DEBUG,
    )

    logger.info('Terminate')
