# syntax=docker/dockerfile:1
FROM seanhorner/utopia_backend_base_image

LABEL maintainer="sean.horner@smoothstack.com"
LABEL project="utopia_airlines"

# Changing working directory to the system user's home repository
WORKDIR /home/utopian
# Copying the necessary files into the application folder
COPY                \
# From context
    app.py          \
    boot.sh         \
    config.py       \
    models.py       \
    networking.py   \
    resources.py    \
    schemas.py      \
    tests.py        \
# To working directory
    ./
# Ensuring that the entry_script has execution permissions
RUN chmod +x boot.sh

# Setting the FLASK_APP environmental variable
ENV FLASK_APP app.py

# Setting the DB_ACCESS_URI and SECRET_KEY environmental variables to their secrets mount
ENV DB_ACCESS_URI /run/secrets/utopia_db_uri
ENV SECRET_KEY /run/secrets/utopia_secret_key

# Ensuring that the system user has the appropriate permissions to run the application
RUN chown -R utopian:utopian ./
# Switching to the system user to run the image
USER utopian

# Exposing port 5000 for Flask interactions
EXPOSE 5000

# Setting the entry_script as the images entrypoint
ENTRYPOINT ["./boot.sh"]
