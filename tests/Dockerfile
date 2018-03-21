ARG PYTHON_VERSION
FROM python:$PYTHON_VERSION

VOLUME /opt
WORKDIR /opt

COPY . /tmp/
RUN pip install /tmp/ && \
    pip install -r /tmp/requirements-dev.txt

CMD ["python", "-m", "pytest", "/opt/tests"]
