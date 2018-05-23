Generating A Spec
=================

The ``pgbedrock generate`` command creates a spec given a database's current state, printing its
results to ``STDOUT``. As a result, one can create a spec with:

    .. code-block:: bash

        docker run -it \
            quay.io/squarespace/pgbedrock generate \
            -h myhost.mynetwork.net \
            -p 5432 \
            -d mydatabase \
            -U mysuperuser \
            -w supersecret > path/to/spec.yml

Alternatively, if you'd prefer to use the Python command-line interface instead, pip install
pgbedrock and run the above command starting from ``pgbedrock generate``. The rest of the command
is identical.

Note that a generated spec may differ from reality due to simplifications that pgbedrock makes. For
an example, see the "pgbedrock simplifies permissions down to read vs. write" bullet in the
:ref:`Notable Functionality And Caveats`. As a result, after generating a spec it is recommended
to run ``pgbedrock configure`` against it right away in check mode to see what differences exist.

In addition to roles being granted various missing write privileges, another common change seen
after running ``pgbedrock generate`` is various default privilege grants occurring. If within the
database there is currently a default privilege granted to a role within a schema, pgbedrock assumes
that the grantee is intended to have this default privilege regardless of who creates the future
object. To do this in Postgres correctly, pgbedrock needs to grant that default privileges from all
roles that could create new objects (see the "Default privileges are granted for permissions like
``myschema.*``" bullet in the :ref:`Notable Functionality And Caveats` section for more details).
