Making Configuration Changes
============================

The ``pgbedrock configure`` command takes a set of parameters for connecting to a database and a
path to a YAML spec and modifies the database so that it matches the spec file. In check mode these
changes will be reported but not committed.

One can configure a database with:

    .. code-block:: bash

        docker run -it \
            -e "JDOE_PASSWORD=${JDOE_PASSWORD}" \
            -e "JSMITH_PASSWORD=${JSMITH_PASSWORD}" \
            -v /path/to/spec.yml:/opt/spec.yml \
            quay.io/squarespace/pgbedrock configure spec.yml \
            -h myhost.mynetwork.net \
            -p 5432 \
            -d mydatabase \
            -U mysuperuser \
            --prompt \
            --check \
            --attributes \
            --memberships \
            --no-ownerships \
            --no-privileges

A few notes on the above:

    * We use ``-it`` here because we are not providing a password as an input variable. Instead, we
      will bring up an interactive password prompt (via ``--prompt``). If we instead just passed in
      a password with ``-w`` then we would not need to use ``-it``.
    * We use ``-t`` so docker allocates a pseudo-tty for us, which allows us to see the progress
      bars as pgbedrock works. This isn't strictly necessary if you don't want to see the progress
      bars.
    * Because our spec.yml has templated passwords for the jdoe and jsmith roles, we pass in the
      environment variables for those passwords to our docker container (note that here we're
      passing them from environment variables in our own environment; obviously you could just
      hard-code them in if you wanted, i.e. ``-e "JDOE_PASSWORD=rumplestiltskin"``).
    * The role we provide with ``-U`` must be a superuser since they will need the ability to
      modify roles, memberships, schema ownership, and privileges.
    * We use ``--prompt`` to have an interactive prompt come up for us to put in our password.
    * We use ``--check`` to be sure that our changes will run in check mode, meaning that we will
      see what pgbedrock *would* change, but it will not actually commit those changes to our
      database cluster at the end of execution. Note that check mode is the default, so we would
      not have to provide this flag, but it is still a good idea to do so to be safe and explicit.
      If we wanted the changes pgbedrock makes to be committed we would instead use the ``--live``
      flag.
    * We choose to run only the attributes and memberships submodules here. In general it is a good
      idea to run all of the submodules (which is the default), but it can be useful to only use a
      subset if you are just tweaking a spec and checking what would change.

Further details on the meanings of parameters that pgbedrock accepts can be found by running
``docker run quay.io/squarespace/pgbedrock configure --help``.

Also note that above we are running pgbedrock through a docker container, but if you'd prefer to
use the Python command-line interface instead, pip install pgbedrock and run the above command
starting from ``pgbedrock configure``. The rest of the command is identical. Note that any
environment variables that you have templated into your spec.yml file must be set within your shell.
