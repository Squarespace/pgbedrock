.PHONY: attach build build_tester clean coverage create_network docs psql release_pypi release_pypitest release_quay remove_network start_postgres stop_postgres test test_one_pg_version test27 test36 view_docs wait_for_postgres

SUPPORTED_PG_VERSIONS ?= 9.5.13 9.6.4 10.4
# The default Postgres that will be used in individual targets
POSTGRES_VERSION ?= 10.4

COMPOSED_NETWORK = pgbedrock_network
POSTGRES_HOST = pgbedrock_postgres
POSTGRES_DB = test_db
POSTGRES_USER = test_user
POSTGRES_PASSWORD = test_password

FULL_NAME = quay.io/squarespace/pgbedrock
VERSION = `grep "^__version__" pgbedrock/__init__.py | cut -d "'" -f 2`


attach:
	@docker run -it --entrypoint "/bin/bash" pgbedrock

build: clean
	@echo "Building the prod docker image"
	docker build \
		-t $(FULL_NAME) \
		-t $(FULL_NAME):$(VERSION) \
		-t $(FULL_NAME):latest \
        .

build_tester:
	@echo "Building the tester27 and tester36 docker images"
	docker build . \
        -f tests/Dockerfile \
        --build-arg PYTHON_VERSION=2.7 \
        -t tester27
	docker build . \
        -f tests/Dockerfile \
        --build-arg PYTHON_VERSION=3.6 \
        -t tester36

clean:
	@echo "Cleaning the repo"
	@find . -name '__pycache__' -type d -exec rm -rf {} +
	@find . -name '*.pyc' -delete
	@find . -name '*.retry' -delete

coverage: start_postgres wait_for_postgres
	pytest --cov pgbedrock/ --cov-report=term-missing:skip-covered

create_network: remove_network
	@echo "Creating the docker network"
	@docker network create $(COMPOSED_NETWORK)

docs:
	$(MAKE) -C docs html O=-nW

psql:
	@docker exec -it $(POSTGRES_HOST) psql -d $(POSTGRES_DB) -U $(POSTGRES_USER)

release_pypi: test
	@echo "Releasing Python package to pypi"
	rm -rf dist/
	python setup.py sdist bdist_wheel
	twine upload -r pypi ./dist/*
	rm -rf dist/

release_pypitest: test
	@echo "Releasing Python package to pypitest"
	rm -rf dist/
	python setup.py sdist bdist_wheel
	twine upload -r pypitest ./dist/*
	rm -rf dist/

# Note: you may have to do a `docker login` and/or be added to the
# admin users for the docker repo before quay will accept a push
release_quay: test build
	@echo "Releasing docker image to quay"
	docker push $(FULL_NAME):$(VERSION)
	docker push $(FULL_NAME):latest

remove_network: stop_postgres
	@echo "Removing the docker network (if it exists)"
	-docker network rm $(COMPOSED_NETWORK) || true

start_postgres: create_network
	@echo "Starting postgres $(POSTGRES_VERSION)"
	@docker run --rm -d --name $(POSTGRES_HOST) \
        -e POSTGRES_USER=$(POSTGRES_USER) \
        -e POSTGRES_PASSWORD=$(POSTGRES_PASSWORD) \
        -e POSTGRES_DB=$(POSTGRES_DB) \
		-p 54321:5432 \
        --net=$(COMPOSED_NETWORK) \
        postgres:$(POSTGRES_VERSION)

stop_postgres:
	@echo "Stopping postgres (if it is running)"
	@-docker stop $(POSTGRES_HOST) || true

test_one_pg_version: start_postgres wait_for_postgres test27 test36 remove_network clean

test: clean build_tester
	@for pg_version in ${SUPPORTED_PG_VERSIONS}; do \
        echo "\n\n\n\n\n\n\nTesting Postgres $$pg_version"; \
        $(MAKE) test_one_pg_version POSTGRES_VERSION="$$pg_version"; \
    done

test27:
	@echo "Running pytest with Python 2.7"
	@docker run \
        --rm \
        -e WITHIN_DOCKER_FLAG=true \
        -e POSTGRES_PORT=5432 \
        -v $(shell pwd):/opt \
        --net=$(COMPOSED_NETWORK) \
        tester27

test36:
	@echo "Running pytest with Python 3.6"
	@docker run \
        --rm \
        -e WITHIN_DOCKER_FLAG=true \
        -e POSTGRES_PORT=5432 \
        -v $(shell pwd):/opt \
        --net=$(COMPOSED_NETWORK) \
        tester36

wait_for_postgres:
	@echo 'Sleeping while postgres starts up';
	@docker run --rm -it --name wait_for_postgres \
        -e POSTGRES_HOST=$(POSTGRES_HOST) \
        -e POSTGRES_USER=$(POSTGRES_USER) \
        -e POSTGRES_PASSWORD=$(POSTGRES_PASSWORD) \
        -e POSTGRES_DB=$(POSTGRES_DB) \
        -e POSTGRES_VERSION=$(POSTGRES_VERSION) \
		-v $(shell pwd)/tests/wait_for_postgres.sh:/wait_for_postgres.sh \
        --net=$(COMPOSED_NETWORK) \
		--entrypoint="/wait_for_postgres.sh" \
        postgres:$(POSTGRES_VERSION)

view_docs: docs
	open docs/_build/html/index.html
