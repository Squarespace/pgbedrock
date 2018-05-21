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
    pip3 install -e . -r requirements-dev.txt

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
2. Push a new git tag to the repo by doing:

    * Write the tag message in a dummy file called ``tag_message``. We do this to allow multi-line tag
      messages
    * ``git tag x.x.x -F tag_message``
    * ``git push --tags origin master``

3. Run ``make release-pypi``.
4. Run ``make release-quay``. This may require doing a docker login to quay first.
