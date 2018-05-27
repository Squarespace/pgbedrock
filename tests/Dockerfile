ARG PYTHON_VERSION
FROM python:$PYTHON_VERSION

VOLUME /opt
WORKDIR /opt

COPY . /tmp/
RUN pip install /tmp/ && \
    pip install -r /tmp/requirements-dev.txt

# We generate a coverage report in order to send this to coveralls from Travis CI. We also
# specify `--cov-report=` do not show the report in all of our output
CMD ["python", "-m", "pytest", "/opt/tests", "--cov", "/opt/pgbedrock", "--cov-report", "term-missing"]
