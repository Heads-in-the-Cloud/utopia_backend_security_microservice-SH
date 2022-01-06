import os

BOOKS_API = os.environ.get("BOOKS_API") or "http://bookings:5000/api"
DATAPROD = os.environ.get("DATAPROD") or "http://data_prod:5000/api"
FLIGHTS_API = os.environ.get("FLIGHTS_API") or "http://flights:5000/api"
SECURITY = os.environ.get("SECURITY") or "http://security/5000"
USERS_API = os.environ.get("USERS_API") or "http://users:5000/api"
ADMIN_ADDR = os.environ.get("ADMIN_ADDR") or "http://admin:5000"
