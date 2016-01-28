# View

API_SECRET_KEY = 'f556bae6-abd5-42b3-b5d4-e4e340f811c7'


# DB

DB_TYPE = 'sql'  # sql / mongo
SQL_DB_URL = 'sqlite:///:memory:'
MONGO_DB_URL = None


# Auth

AUTH_METHODS = ('simple', 'facebook')


# Log

LOG_LEVEL = 'DEBUG'
LOG_FILENAME__SYSTEM = './logs/system.log'
LOG_FILENAME__APP = './logs/app.log'
LOG_FILENAME__SQL = './logs/sql.log'
LOG_FILENAME__VIEW = './logs/view.log'


# Flask

FLASK_HOST = 'localhost'
FLASK_PORT = 8080
FLASK_DEBUG = False
