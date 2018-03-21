FROM python:3.6

VOLUME /opt
WORKDIR /opt

COPY setup.py /opt/
COPY pgbedrock /opt/pgbedrock
RUN pip install .

ENTRYPOINT ["pgbedrock"]
