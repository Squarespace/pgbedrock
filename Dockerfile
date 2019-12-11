FROM python:3.6

VOLUME /opt
WORKDIR /opt

COPY setup.py /opt/
COPY requirements.txt /opt/
COPY pgbedrock /opt/pgbedrock
RUN pip install -r requirements.txt
RUN pip install .
RUN pip install --force-reinstall psycopg2

ENTRYPOINT ["pgbedrock"]
