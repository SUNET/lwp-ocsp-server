FROM python:3.12

ENV PIP_INDEX_URL=https://pypi.sunet.se/simple

RUN python3 -m pip install poetry

COPY poetry.lock pyproject.toml /

RUN poetry config virtualenvs.create false \
  && poetry install --no-interaction --no-ansi

COPY ocsp-server.py /ocsp-server.py

EXPOSE 5000/tcp
ENTRYPOINT [ "/ocsp-server.py" ]
