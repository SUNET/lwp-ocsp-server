FROM python:3.12

ENV PIP_INDEX_URL=https://pypi.sunet.se/simple


COPY requirements.txt /
RUN python3 -m pip install -r /requirements.txt --require-hashes

COPY ocsp-server.py /ocsp-server.py

EXPOSE 5000/tcp
ENTRYPOINT [ "/ocsp-server.py" ]
