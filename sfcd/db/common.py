import sfcd.db.sql.engine
# import sfcd.db.mongo.engine


def get_db_engine(config):
    if config.db.type == 'sql':
        return sfcd.db.sql.engine.DBEngine(config.db.url)
    elif config.db.type == 'mongo':
        return None
        # return sfcd.db.mongo.engine.DBEngine(config.db.url)
