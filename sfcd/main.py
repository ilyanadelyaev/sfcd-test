import sfcd
import sfcd.config


if __name__ == '__main__':
    # get db params from config
    db_type = sfcd.config.DB_TYPE
    db_url = None
    if sfcd.config.DB_TYPE == 'sql':
        db_url = sfcd.config.SQL_DB_URL
    elif sfcd.config.DB_TYPE == 'mongo':
        db_url = sfcd.config.MONGO_DB_URL

    # create app
    sfcd.app = sfcd.Application(db_type, db_url)

    # run web app
    sfcd.app.web_view.run(
        host=sfcd.config.FLASK_HOST,
        port=sfcd.config.FLASK_PORT,
        debug=sfcd.config.FLASK_DEBUG,
    )
