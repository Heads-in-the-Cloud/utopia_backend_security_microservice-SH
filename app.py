import os

from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import datetime
from functools import wraps

from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager


app = Flask(__name__)
app.config['FLASK_ENV'] = 'development'
app.config['SECRET_KEY'] = str(os.getenv('SECRET_KEY'))
app.config['JWT_SECRET_KEY'] = str(os.getenv('SECRET_KEY'))
app.config['SQLALCHEMY_DATABASE_URI'] = f"mysql://utopiaAdmin:{os.getenv('RDS_PSWD')}@{os.getenv('RDS_INST')}/utopia"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


db = SQLAlchemy(app)
jwt = JWTManager(app)


# @app.route('/register', methods=['GET', 'POST'])
# def signup_user():
#     data = request.get_json()
#
#     hashed_password = generate_password_hash(data['password'], method='sha256')
#
#     new_user = Users(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)
#     db.session.add(new_user)
#     db.session.commit()
#
#     return jsonify({'message': 'registered successfully'})


@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("username", None)
    password = request.json.get("password", None)
    if username != "test" or password != "test":
        return jsonify({"msg": "Bad username or password"}), 401

    access_token = create_access_token(identity=username)
    return jsonify(access_token=access_token)


if __name__ == '__main__':
    app.run(debug=True)
