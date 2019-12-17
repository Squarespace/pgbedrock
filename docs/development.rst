Development
===========

Several functionalities for testing and debugging are described below.


Debugging With Verbose Mode
---------------------------
To see all queries executed by pgbedrock as it runs, run pgbedrock with the ``--verbose`` flag.
Note that this will likely produce a lot of output, so you may want to tee it into a log file.


Getting Set Up For Local Development
------------------------------------
First, get your Python environment set up:

.. code-block:: bash

    mkvirtualenv pgbedrock3 --python python3
    pip3 install -e . -r requirements-dev.txt -r requirements-publish.txt

Note that if the pip install step fails on psycopg2 you may have to do the following:

    * ``brew install postgresql openssl``
    * ``xcode-select --install``, followed by a restart of your machine
    * If you still get an error about a library for -lssl not found, then you have two options: ``brew reinstall python`` to get Python to use brew's OpenSSL, or explicitly tell pip to use Brew's OpenSSL via ``LDFLAGS="-L$(brew --prefix openssl)/lib" pip3 install psycopg2``.

Testing Functionality
---------------------
Various testing functionality exists:

    * ``make test`` - Run tests for both Python 2 and 3 (via docker containers) against all
      supported Postgres versions
    * ``pytest`` - Run tests for whichever Python version is in your virtualenv. This requires
      running ``make start_postgres`` first to start up a local dockerized Postgres. Also, if
      you've previously run the test suite with docker that you will need to run ``make clean``
      first to clear out pytest's cache or else pytest will error out.
    * ``make coverage`` - Check package coverage and test coverage


Releasing A New Version
-----------------------
If you make a PR that gets merged into master, a new version of pgbedrock can be created as follows.

1. Increment the ``__version__`` in the ``pgbedrock/__init__.py`` file and commit that change.
2. Update the `CHANGELOG` file calling out changes to code regarding added features, new behaviors that could introduce breaking changes, and credits.
3. Update `CONTRIBUTORS`, adding new contributors alphabetically according to `git log --format=%an | sort | uniq`, excluding duplicates and correcting author names as requested by contributors.
4. Push a new git tag to the repo by doing:

    * Write the tag message in a dummy file called ``tag_message``. We do this to allow multi-line tag
      messages
    * ``git tag x.x.x -F tag_message``
    * ``git push --tags origin master``

3. Run ``make release-pypi``.
4. Run ``make release-quay``. This may require doing a docker login to quay first.
