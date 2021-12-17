import os
basedir = os.path.abspath(os.path.dirname(__file__))


class Config(object):
    FLASK_ENV = 'development'
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'this-is-a-bad-key-bro'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_DATABASE_URI = os.getenv('UTOPIA_DB_URI') or "sqlite:///" + os.path.join(basedir, "test.db")
