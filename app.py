from datetime import datetime, timedelta
import os
from functools import wraps

import jwt

from flask import Flask, request, make_response, jsonify, redirect
from flask_migrate import Migrate
from werkzeug.security import check_password_hash

from config import Config

from networking import *

app = Flask(__name__)
app.config.from_object(Config)

# Initializing the SQLAlchemy ORM database created in the models.py file
from models import db
db.init_app(app)

# Initializing Marshmallow serialization schemas
from schemas import *
ma.init_app(app)

# Initializing the routes
from routes import *

# Initializing the Flask-Migration Handler
migrate = Migrate(db, app)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        elif 'token' in request.args:
            token = request.args.get('token')
        else:
            return redirect(f'{ADMIN_ADDR}/login')

        try:
            data = jwt.decode(
                token,
                app.config['SECRET_KEY'],
                algorithms="HS256"
            )
            current_user = User.query           \
                .filter_by(email=data['email']) \
                .first()
        except Exception as e:
            response_obj = {
                'status': 'fail',
                'message': 'Something odd happened, try again.'
            }
            print(e)
            return make_response(jsonify({response_obj})), 403

        return f(*args, **kwargs)
    return decorated


@app.route('/')
def index():
    if not 'x-access-token' in request.headers or not 'token' in request.args:
        return redirect(f'{ADMIN_ADDR}/login')
    else:
        return 'Security microservice is up and running.'


@app.route('/reauth')
@token_required
def reauthorization():
    if 'x-access-token' in request.headers:
        token = request.headers['x-access-token']
    else:
        token = request.args.get('token')
    # Pull the data from the previous token
    data = jwt.decode(token, app.config['SECRET_KEY'], algorithms="HS256")
    # Change the expiration time to 8 min from "now" (leave username and initial creation time to pass through)
    data['exp'] = datetime.utcnow() + timedelta(minutes=8)
    # Create a new token for the user
    token = jwt.encode(data, app.config['SECRET_KEY'], algorithm="HS256")
    # Pass that new token back to the user to use, so their browsing isn't interrupted
    return make_response(jsonify({'token': token}), 201)


@app.route('/login')
def login():
    auth = request.form

    if not auth or not auth.get('email') or not auth.get('password'):
        # If there is no auth data, or the email or password is missing, throws a 401 error
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate': 'Basic realm="Login Required"'}
        )

    user = User.query.filter_by(email=auth.get('email')).first()

    if not user:
        # User must not exist, throws a 401 error
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate': 'Basic realm="Login Required"'}
        )

    if check_password_hash(user.password, auth.get('password')):
        # If the user exists in the registry and the password matches the hash in the registry, give them a token
        token = jwt.encode({
            'user_id': user.id,
            'exp': datetime.utcnow() + timedelta(minutes=8),
            'iat': datetime.utcnow()},
            app.config['SECRET_KEY'],
            algorithm="HS256")

        return make_response(jsonify({'token': token}), 201)

    return make_response(
        'Wrong password!',
        403,
        {'WWW-Authenticate': 'Basic Realm="Login Required"'}
    )


if __name__ == '__main__':
    app.run(debug=True)
