pgbedrock
=========
|travis_ci| |coveralls| |postgres_versions| |pip_versions|

.. |travis_ci| image:: https://travis-ci.org/Squarespace/pgbedrock.svg?branch=master
    :target: https://travis-ci.org/Squarespace/pgbedrock

.. |coveralls| image:: https://coveralls.io/repos/github/Squarespace/pgbedrock/badge.svg?branch=master
    :target: https://coveralls.io/github/Squarespace/pgbedrock?branch=master

.. |postgres_versions| image:: https://img.shields.io/badge/postgres-9.5,_9.6,_10-blue.svg

.. |pip_versions| image:: https://img.shields.io/pypi/pyversions/pgbedrock.svg
    :target: https://pypi.python.org/pypi/pgbedrock


pgbedrock is an application for managing the roles, memberships, ownerships, and most importantly
the permissions for tables, sequences, and schemas in a Postgres database.

Given the parameters to connect to a Postgres database (i.e. host, port, etc.) and a YAML file (a
"spec") representing the desired database configuration, pgbedrock makes sure that the configuration
of that database matches the spec. If there are differences, it will alter the database to make it
match the spec.

It can be run as a docker container (via ``docker run quay.io/squarespace/pgbedrock``) or
as a local command-line utility (via ``pip install pgbedrock``).

Detailed information can be found in the `documentation`_.

.. _documentation: https://pgbedrock.readthedocs.io/en/latest/

Example
-------
As an example, the definition for the ``jdoe`` role in the spec might look like this:

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

When pgbedrock is run, it would make sure that:

    * The role ``jdoe`` exists
    * ``jdoe`` can log in
    * ``jdoe`` is not a superuser
    * ``jdoe``'s password is the same as what is in the ``$JDOE_PASSWORD`` environment variable
    * All other role attributes for ``jdoe`` are the Postgres defaults (as defined by `pg_authid`_).
    * ``jdoe`` is a member of the ``analyst`` role
    * ``jdoe`` is a member of no other roles
    * ``jdoe`` owns the ``finance_reports`` schema
    * ``jdoe`` owns the ``finance_reports.Q2_revenue`` and ``finance_reports.Q2_margin`` tables
    * ``jdoe`` has read-level schema access (in Postgres terms: ``USAGE``) for the ``finance`` and
      ``marketing`` schemas
    * ``jdoe`` has write-level schema access (``CREATE``) for the ``reports`` schema
    * ``jdoe`` has read-level access (``SELECT``) to all tables in the ``finance`` schema and to the
      ``marketing.ad_spend`` and ``marketing.impressions`` tables
    * ``jdoe`` has default privileges to read from all future tables created in the ``finance`` schema
    * ``jdoe`` has write-level access (``SELECT``, ``INSERT``, ``UPDATE``, ``DELETE``, ``TRUNCATE``,
      ``REFERENCES``, and ``TRIGGER``) to all tables in the ``reports`` schema
    * ``jdoe`` has default privileges to write to all future tables created in the ``reports`` schema
    * ``jdoe`` has write-level access (``SELECT``, ``USAGE``, ``UPDATE``) to all sequences in the
      ``reports`` schema
    * ``jdoe`` has default privileges to write to all future sequences created in the ``reports`` schema
    * ``jdoe`` does not have any access other than that listed above (except whatever it inherits
      from the ``analyst`` role that ``jdoe`` is a member of)

    .. _pg_authid: https://www.postgresql.org/docs/9.6/static/catalog-pg-authid.html


Quickstart
----------
Using pgbedrock requires three steps: generating a spec for a database, reviewing that spec, and
configuring the database using that spec. Below we will do this using the pgbedrock docker image,
but these steps can also be done with the pip-installed version of the tool.

#. **Generate a spec for a database**. Specify the connection parameters below (host, port,
   database, username, and user password) as well as the place to output the tentative spec. Note
   that the user passed with ``-U`` must be a superuser.

   .. code-block:: bash

       docker run -it \
           quay.io/squarespace/pgbedrock generate \
           -h myhost.mynetwork.net \
           -p 5432 \
           -d mydatabase \
           -U mysuperuser \
           -w supersecret > path/to/spec.yml


#. **Review the spec**. pgbedrock is not quite as flexible as Postgres's permissioning, and as a
   result the generated spec may differ slightly from the current state of your database. For more
   information on these potential simplifications, see the `Notable Functionality And Caveats`_
   section in the docs.  As a result, it is recommended to run ``pgbedrock configure`` in check mode
   the first time you use it to see what changes it would introduce to your current setup. This
   looks similar to the command above, but requires us to also pass in the passwords for any roles
   whose passwords are managed within Postgres itself. These can be identified in the spec file as
   roles with a line that looks like ``PASSWORD "{{ env['MYROLE_PASSWORD'] }}"`` (if you forget to
   pass in these passwords pgbedrock will just throw an error and refuse to run). Note that you must
   run ``pgbedrock configure`` against the Postgres primary. To run pgbedrock in check mode we do
   the following:

   .. _Notable Functionality And Caveats: https://pgbedrock.readthedocs.io/en/latest/notable_functionality_and_caveats.html

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
           -w supersecret \
           --check

   Note that ``--check`` is actually the default behavior, so we could also omit that.


#. **Configure the database using the spec**. Once you feel comfortable with the changes pgbedrock
   would introduce, run the above command again using ``--live`` instead of ``--check``. Changes
   will now be made real. To make future changes, modify the spec file and run the above command.

For further information, see the `documentation`_.


License
-------
Copyright 2018 Squarespace, Inc.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
in compliance with the License. You may obtain a copy of the License at:

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License
is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied. See the License for the specific language governing permissions and limitations under
the License.
