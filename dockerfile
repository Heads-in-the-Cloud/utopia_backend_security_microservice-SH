# syntax=docker/dockerfile:1
FROM 026390315914.dkr.ecr.us-west-2.amazonaws.com/utopia_backend_base_image-sh

MAINTAINER Sean Horner "sean.horner@smoothstack.com"
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
    schemas.py      \
    tests.py        \
# To working directory
    ./
# Ensuring that the entry_script has execution permissions
RUN chmod +x boot.sh

# Setting the FLASK_APP environmental variable
ENV FLASK_APP app.py

# Ensuring that the system user has the appropriate permissions to run the application
RUN chown -R utopian:utopian ./
# Switching to the system user to run the image
USER utopian

# Exposing port 5000 for Flask interactions
EXPOSE 5000

# Setting the entry_script as the images entrypoint
ENTRYPOINT ["./boot.sh"]
