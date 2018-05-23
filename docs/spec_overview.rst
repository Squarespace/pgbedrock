Spec Overview
=============

At A Glance
-----------
The spec.yml file is a YAML document that holds all information about roles, role memberships,
object ownerships, and privileges for a given database. It is best generated programmatically with
``pgbedrock generate``.

The spec.yml is comprised of a number of role definitions. An example role definition within
this file may look something like the below:

    .. code-block:: bash

        jdoe:
            can_login: yes
            is_superuser: no
            attributes:
                - PASSWORD "{{ env['JDOE_PASSWORD'] }}"
            member_of:
                - analyst
            owns:
                schemas:
                    - finance_reports
                tables:
                    - finance_reports.Q2_revenue
                    - finance_reports.Q2_margin
            privileges:
                schemas:
                    read:
                        - finance
                        - marketing
                    write:
                        - reports
                tables:
                    read:
                        - finance.*
                        - marketing.ad_spend
                        - marketing.impressions
                    write:
                        - reports.*
                sequences:
                    write:
                        - reports.*

All items other than the role name itself are optional. As a result, if you wanted to create a role
``foo`` with all defaults you could do so with just:

    .. code-block:: bash

        foo:

A role definition can include any of the keywords listed below.


Keywords
--------

attributes
^^^^^^^^^^
    ====   =======
    Type   Default
    ====   =======
    list   Empty
    ====   =======

    Items in the list may be any of the following attributes accepted by Postgres's `CREATE ROLE`_
    statement. Most attributes can be preceeded by 'NO' to negate them:

        =========================    =============
        Keyword                      Default
        =========================    =============
        BYPASSRLS                    NOBYPASSRLS
        CONNECTION LIMIT <int>       -1
        CREATEDB                     NOCREATEDB
        CREATEROLE                   NOCREATEROLE
        INHERIT                      INHERIT
        PASSWORD <password>          None
        REPLICATION                  NOREPLICATION
        VALID UNTIL <date string>    'infinity'
        =========================    =============

    .. _CREATE ROLE: https://www.postgresql.org/docs/9.6/static/sql-alterrole.html


can_login
^^^^^^^^^
    ====   =======
    Type   Default
    ====   =======
    bool   False
    ====   =======


has_personal_schema
^^^^^^^^^^^^^^^^^^^
    ====   =======
    Type   Default
    ====   =======
    bool   False
    ====   =======

    Whether the role should have a personal schema as defined in the "personal_schemas are supported"
    bullet in :ref:`Notable Functionality And Caveats`.


is_superuser
^^^^^^^^^^^^
    ====   =======
    Type   Default
    ====   =======
    bool   False
    ====   =======


member_of
^^^^^^^^^
    ====   =======
    Type   Default
    ====   =======
    list   Empty
    ====   =======

    The roles that this role is a member of. Within Postgres, this means that if ``roleA`` is a member
    of ``roleB``, then ``roleA`` will inherit all privileges that ``roleB`` has.


owns
^^^^
    ====   =======
    Type   Default
    ====   =======
    dict   Empty
    ====   =======

    The objects that this role owns. At present pgbedrock manages schema, table, and sequence ownership.
    Each of these objects is provided as a keyword followed by a list of the objects of that kind that
    is owned by this role. For example:

    .. code-block:: bash

        analyst:
            owns:
                schemas:
                    - finance
                sequences:
                    - finance.*
                tables:
                    - finance.*
                    - marketing.ad_spend


privileges
^^^^^^^^^^
    ====   =======
    Type   Default
    ====   =======
    dict   Empty
    ====   =======

    The privileges section may be easiest to explain with an example:

    .. code-block:: bash

        analyst:
            can_login: no
            privileges:
                schemas:
                    read:
                        - finance
                        - marketing
                    write:
                        - reports
                tables:
                    read:
                        - finance.*
                        - marketing.*
                    write:
                        - reports.*

    Here we have a role ``analyst`` that will be used as a group role (i.e. it has no login access, but
    we will grant it to each of our analyst employees so that they inherit its permissions). We have
    given this analyst role read access on the finance and marketing schemas and to all tables in them,
    as well as write access to the reports schema and to all tables in it.

    The above example shows the general structure of the privileges section: the first keys within it
    are the object types. pgbedrock currently supports schemas, sequences, and tables as object types,
    each of which is optional to include. Within each object type, we have keys for read and write, also
    both optional. Under each of these entries we have a list of the items to grant to.

    Note that the ``foo.*`` syntax is not a regex expression but rather a shorthand for listing
    everything in the schema. As a result, putting ``foo.bar*`` (to get tables ``foo.barn`` or
    ``foo.barbados``) won't work; only ``foo.*`` will work.

Password Management
-------------------
Password management deserves some additional clarification. Since passwords shouldn't be stored in
plain text in version control, pgbedrock takes user-provided environment variables to fill in
passwords. For example, one could have a role defined as:

.. code-block:: bash

    myrole:
        attributes:
            - PASSWORD "{{ env['MYROLE_PASSWORD'] }}"

Note that the environment variable can be named whatever you would like. As long as that variable
exists in the environment, pgbedrock will use it. If a variable is declared in the spec template
but does not exist in the environment, pgbedrock will refuse to run and will report the name of the
missing environment variable in its error message.

Note that if you are running pgbedrock through docker you will need to pass these environment
variables into the docker container. This can be done using the ``-e`` flag for docker run as shown
in the example for the :ref:`Making Configuration Changes` section above.
