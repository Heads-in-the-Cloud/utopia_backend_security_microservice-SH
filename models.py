# ######################################################################################################################
# ########################################                               ###############################################
# ########################################       SQLAlchemy Models       ###############################################
# ########################################                               ###############################################
# ######################################################################################################################
import datetime
import os

import flask_bcrypt
import jwt
from flask_sqlalchemy import SQLAlchemy

SECRET_KEY = os.getenv('SECRET_KEY')

# Initializing the SQLAlchemy Database ORM
db = SQLAlchemy()

# ------------------------------------------------
#                   Models Tables
# ------------------------------------------------


class User(db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    role_id = db.Column(db.Integer, db.ForeignKey("role_id.id"), nullable=False)
    given_name = db.Column(db.String, nullable=False)
    family_name = db.Column(db.String, nullable=False)
    username = db.Column(db.String, nullable=False)
    password = db.Column(db.String, nullable=False)
    email = db.Column(db.String, nullable=False)
    phone = db.Column(db.String)

    def __init__(self, given_name, family_name, email, username, password, role_id=1, phone=""):
        self.role_id = role_id
        self.given_name = given_name
        self.family_name = family_name
        self.email = email
        self.username = username
        self.password = flask_bcrypt.generate_password_hash(password).decode()
        self.phone = phone

    @staticmethod
    def encode_auth_token(self, user_id):
        """
        Generates a JWT authorization token
        :param user_id: the ID of the user attempting to log in
        :return: string
        """
        try:
            payload = {
                'exp': datetime.datetime.utcnow() + datetime.timedelta(days=0, seconds=5),
                'iat': datetime.datetime.utcnow(),
                'sub': user_id
            }
            return jwt.encode(
                payload,
                SECRET_KEY,
                algorithm='HS256'
            )
        except Exception as e:
            return e

    @staticmethod
    def decode_auth_token(auth_token):
        """
        Decodes a JWT authorization token
        :param auth_token:
        :return: integer|string
        """
        try:
            payload = jwt.decode(auth_token, SECRET_KEY)
            return payload['sub']
        except jwt.ExpiredSignatureError:
            return "Signature expired. Please log in again."
        except jwt.InvalidTokenError:
            return 'Invalid token. Please log in again.'
