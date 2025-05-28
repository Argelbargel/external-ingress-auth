FROM python:3.13.3-alpine

ENV PYTHONUNBUFFERED=1 \
    CRYPTOGRAPHY_DONT_BUILD_RUST=1

RUN apk --no-cache add build-base libffi-dev openssl-dev openldap-dev

ENV USER=aldap \
    UID=10001 \
    GROUP=aldap \
    GID=10001
ENV HOME=/home/$USER
RUN addgroup -g $GID -S $GROUP && adduser -u $UID -S $USER -G $GROUP;

COPY ./files/requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt --no-cache-dir

WORKDIR $HOME
COPY --chown=$UID:$GID ./files/ .
RUN chmod +x ./service.sh
USER $UID:$GID

ENV DEV_MODE=false \
    GUNICORN_CMD_ARGS=""

ENTRYPOINT [ "./service.sh" ]