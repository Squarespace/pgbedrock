# pgbedrock

## What Is pgbedrock?
pgbedrock is an application for managing the roles, memberships, schema ownership, and most
importantly the permissions for tables, sequences, and schemas in a Postgres database. It takes
the parameters to connect to a Postgres database (i.e. host, port, etc.) and a YAML file (a 'spec')
representing the desired database configuration and will make sure that the configuration of that
database matches the spec. If there are differences, it will change the database configuration
to make it match the spec.

As an example, the definition for the 'jdoe' role in the spec might look like this:
```
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
```

When pgbedrock is run, it would make sure that:
* The role jdoe exists
* jdoe can log in
* jdoe is not a superuser
* jdoe's password is the same as what is in the `$JDOE_PASSWORD` environment variable
* All other role attributes for jdoe are the Postgres defaults (as defined by [pg_authid](https://www.postgresql.org/docs/9.1/static/catalog-pg-authid.html)).
* jdoe is a member of the analyst role
* jdoe is a member of no other roles
* jdoe owns the finance_reports schema
* jdoe has read-level schema access (in Postgres terms: USAGE) for the finance and marketing schemas
* jdoe has write-level schema access (CREATE) for the reports schema
* jdoe has read-level access (SELECT) to all tables in the finance schema and to the
  marketing.ad_spend and marketing.impressions tables
* jdoe has default privileges to read from all future tables created in the finance schema
* jdoe has write-level access (SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, and TRIGGER) to all tables in the reports schema
* jdoe has default privileges to write to all future tables created in the reports schema
* jdoe has write-level access (SELECT, USAGE, UPDATE) to all sequences in the reports schema
* jdoe has default privileges to write to all future sequences created in the reports schema
* jdoe does not have any access other than that listed above (except whatever it inherits from the
  'analyst' role that jdoe is a member of)


## Why Is pgbedrock Useful?
pgbedrock was created in order to:
1. **Simplify permission complexity.** pgbedrock simplifies object access down to read vs. write. As a
   result, an administrator doesn't need to know that within Postgres 'read' access is really SELECT
   for tables but USAGE for schemas, or that write access for schemas means CREATE but for tables
   it is a combination of INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, and TRIGGER.
2. **Co-locate all config.** Within Postgres itself, role, role membership, ownership, and permission
   information is distributed across a variety of locations: pg_authid, pg_class, pg_namespace,
   pg_default_acl, and so on. As a result, it is hard to get a high-level "lay of the land".
   pgbedrock puts all this config into one YAML file so it's easy to stay on top of how the
   database is configured.
3. **Assert that config matches reality.** Because information is so distributed in a normal
   Postgres cluster, it is easy for things to get out of sync. pgbedrock checks the YAML spec
   against the provided database and asserts that the two match. If they do not, it makes changes
   to the database to make them match, transparently reporting all of the queries that it ran to
   make those changes.
4. **Provide an auditable log of changes.** By using a YAML spec, our config can be put into source
   control, allowing us to see who had access at any given time. In addition, each time pgbedrock
   runs it will output the set of SQL queries that it ran to bring the cluster in line with the
   spec. By storing those outputs an administrator will have an audit trail of when each
   change occurred.

As a knock-on benefit, by having pgbedrock run on a schedule one can enforce that config changes be
put into code and through a PR process: changes made live to a cluster will be revoked the next
time the tool runs, helping dissuade administrators from continually making live, unaudited changes.


## Usage
pgbedrock can be used either as a docker container or as a command-line utility. In either case,
there are two main functionalities:
* pgbedrock generate - take a set of parameters for connecting to a database and output to STDOUT
  a YAML spec representing that database's configuration. This is typically run once just to get an
  existing postgres database ready to use pgbedrock.
* pgbedrock configure - take a set of parameters for connecting to a database and a path to a YAML
  spec and modify the database so that it matches the spec file. In check mode these changes will
  be reported but not committed.


### Running Via Docker
Assuming you already have docker installed, running pgbedrock just requires a single command. To
configure a database with an existing spec, this command would look like the following:
```
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
```
A few notes on the above:
* We use `-it` here because we are not providing a password as an input variable. Instead, we will
  bring up an interactive password prompt (via `--prompt`). If we instead just passed in a password
  with `-w` then we would not need to use `-it`.
* We use `-t` so docker allocates a pseudo-tty for us, which allows us to see the progress bars as
  pgbedrock works. This isn't strictly necessary if you don't want to see the progress bars.
* Because our spec.yml has templated passwords for the jdoe and jsmith roles, we pass in the
  environment variables for those passwords to our docker container (note that here we're passing
  them from environment variables in our own environment; obviously you could just hard-code them
  in if you wanted, i.e. `-e "JDOE_PASSWORD=rumplestiltskin"`).
* The role we provide with `-U` must be a superuser since they will need the ability to modify
  roles, memberships, schema ownership, and privileges.
* We use `--prompt` to have an interactive prompt come up for us to put in our password.
* We use `--check` to be sure that our changes will run in check mode, meaning that we will see what
  pgbedrock _would_ change, but it will not actually commit those changes to our database cluster at
  the end of execution. Note that check mode is the default, so we would not have to provide this
  flag, but it is still a good idea to do so to be safe and explicit. If we wanted the changes
  pgbedrock makes to be committed we would instead use the `--live` flag.
* We choose to run only the attributes and memberships submodules here. In general it is a good
  idea to run all of the submodules (which is the default), but it can be useful to only use a
  subset if you are just tweaking a spec and checking what would change.

Further details on the meanings of parameters that pgbedrock accepts can be found by running
`docker run quay.io/squarespace/pgbedrock configure --help`.


### Running As A Command-Line Utility
Running as a command-line utility is very similar to the above docker usage, but requires a bit of
setup. First, make sure you have Python 2 or 3 installed, then install the requirements. Ideally
this would be done in a virtual environment:
```
mkvirtualenv pgbedrock --python python3
pip3 install .
```

This installs pgbedrock as a command-line utility. You can now run a command similar to the above
docker command:
```
pgbedrock configure /path/to/spec.yml \
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
```

Note that any environment variables you have templated into your spec.yml file must be active in
your shell.

Further details on the meanings of parameters can be found by running `pgbedrock configure --help`.


## Notable Functionality / Caveats
* **Postgres cluster must be on Postgres 9.0 or greater.** pgbedrock makes use of the default
privilege functionality which was introduced in Postgres 9.0. As a result, pgbedrock will only work
with clusters that are using Postgres 9.0 or greater. Supporting older versions of postgres would
not be difficult and may be added in the future.

* **pgbedrock will not delete or alter any objects.** pgbedrock is explicitly written to not do
anything destructive toward the objects in the database. A revoked permission can simply be
re-granted, but a table/schema/sequence that has been deleted is gone for good (unless you have
backups). As a result, pgbedrock will not delete any objects, including roles or schemas. pgbedrock
will configure roles and schemas, but if they need to be deleted you will have to do that manually.
If a role or schema is not listed in the spec.yml file then pgbedrock will refuse to run, alerting
the user of the discrepancy and asking them to manually take action (i.e. delete the role / schema
or add it to the spec).

* **Management of object ownership is currently supported only for schemas.** Support for managing
ownership of tables, sequences, etc. is planned but not currently supported. At present, table
ownership will be changed only for personal_schemas as described below in 'personal_schemas are
supported'.

* **Privilege management is currently supported only for tables, schemas, and sequences.** Managing
access and ownership to other objects such as functions, foreign data wrappers, foreign servers,
etc. would not be too difficult to implement and that functionality may be added in the future.

* **Roles and memberships are cluster-wide in Postgres**. This means that if you have multiple
databases within one Postgres instance, all of those databases share the same roles and role
memberships. The consequence of this is that if you use pgbedrock to manage all of those databases,
then you will need to list the roles and role memberships in each database's spec file.

* **pgbedrock simplifies permissions down to read vs. write.** In our experience, this is easier to
reason about, easier to remember, and is a sufficient level of granularity for most use cases.
However, a consequence of this is that if you _do_ use more fine-grained controls in your database
then you will need to be more permissive or restrictive in your permissions in order to use
pgbedrock (or, even better, put in a pull request to add support for finer-grained controls to
pgbedrock!). As a concrete example, if roleA currently has INSERT permission to a table, then to
use pgbedrock you will have to decide whether they will get read access (and thus lose that INSERT
permission) or write access (and thus get UPDATE, DELETE, etc. permissions as well). If the spec is
created with `pgbedrock generate`, pgbedrock will take the latter approach (i.e. granting additional
write-level access), so make sure to check the initial spec after generating it to verify that any
changes it introduces are acceptable.

* **Default privileges are granted for permissions like myschema.\*** When a permission grant looks
like 'myschema.\*', pgbedrock interprets that to mean 'grant this permission for all existing
tables _and for all future tables too_ (i.e. a default privilege). However, default privileges in
Postgres are only applied to new tables created by the role that granted the privilege, meaning
that if roleA grants default SELECT privileges on tables to roleB, then those default privileges
will apply if and only if roleA is the one who creates a subsequent table. If instead roleC creates
a table then the default privileges won't happen. To deal with this, when pgbedrock sees
'myschema.\*' it will identify all roles that have the ability to create objects in that schema
and grant default privileges from each of these roles to the role that should have the default
privileges.

* **personal_schemas are supported.** It is common to give users a "sandbox" where they can create
objects, modify them, delete them, etc. A typical way to do this is to create a schema with the same
name as the role and let them own it, i.e. the role jdoe would own the schema jdoe. Every object in
the jdoe schema should thus be owned by jdoe. pgbedrock supports this concept in a few ways. First,
by specifying `has_personal_schema: yes` for a role, a personal schema will be created if it does
not exist. If the schema already exists, pgbedrock will make sure that the schema and all objects
in it that pgbedrock manages are owned by this role, making changes to ownership to make this
true. Finally, personal_schemas can be used as a special term in privilege grants. For example, a
role can be given read-level table privileges to personal_schemas.\*, which will let that role
read all tables in all personal schemas in the database. To be a personal schema, the schema must
be owned by a role with the same name as the schema and that role must be able to login.


## Building A Spec

### Programmatically Generating A Spec
The `pgbedrock generate` command creates a spec given a database's current state, printing its
results to STDOUT. As a result, one can create a spec with:
```
docker run -it \
    quay.io/squarespace/pgbedrock generate \
    -h myhost.mynetwork.net \
    -p 5432 \
    -d mydatabase \
    -U mysuperuser \
    -w supersecret > path/to/spec.yml
```

Note that a generated spec may differ from reality due to simplifications that pgbedrock makes. For
an example, see the "pgbedrock simplifies permissions down to read vs. write." bullet in the
"Notable Functionality / Caveats" section above. As a result, after generating a spec it is
recommended to run `pgbedrock configure` against it right away to see (in check mode) what
differences exist.

In addition to roles being granted various missing write privileges, another common change seen
after running `pgbedrock generate` is various default privilege grants occurring. If within the
database there is currently a default privilege granted to a role within a schema, pgbedrock assumes
that the grantee is intended to have this default privilege regardless of who creates the future
object. To do this in Postgres correctly, pgbedrock needs to grant that default privileges from all
roles that could create new objects (see the "Default privileges are granted for permissions like myschema.\*"
bullet in the "Notable Functionality / Caveats" section above for more details).


### Definition of Items within A Spec
The spec.yml file holds all information about roles, role memberships, schema ownership, and
privileges for a given database. A spec file is a YAML document comprised of a number of role
definitions. For an example of what a role definition may look like, see the "What Is pgbedrock?"
section above.

All items other than the role name itself are optional. As a result, if you wanted to create a role
foo with all defaults you could do so with just:
```
foo:
```

A role definition can include any of the following keys:

**attributes**: list (default: empty)
Items in the list may be any of the following attributes accepted by Postgres's [CREATE ROLE](https://www.postgresql.org/docs/9.6/static/sql-alterrole.html)
statement. Most attributes can be preceeded by 'NO' to negate them:
* BYPASSRLS (default: NOBYPASSRLS)
* CONNECTION LIMIT \<int\> (default: -1)
* CREATEDB (default: NOCREATEDB)
* CREATEROLE (default: NOCREATEROLE)
* INHERIT (default: INHERIT)
* PASSWORD \<password\> (default: None); See more details under "Password Management" below
* REPLICATION (default: NOREPLICATION)
* VALID UNTIL \<date as string\> (default: 'infinity')

**can_login**: boolean (default: False)

**has_personal_schema**: boolean (default: False)
Whether the role should have a personal schema as defined above under the
"personal_schemas are supported" section in "Notable Functionality / Caveats"

**is_superuser**: boolean (default: False)

**member_of**: list (default: empty)
The roles that this role is a member of. Within Postgres, this means that if roleA is a member of
roleB, then roleA will inherit all privileges that roleB has.

**privileges**: dict (default: empty)
The privileges section may be easiest to explain with an example:
```
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
```

Here we have a role "analyst" that will be used as a group role (i.e. it has no login
access, but we will grant it to each of our analyst employees so that they inherit its
permissions). We have given this analyst role read access on the finance and marketing
schemas and to all tables in them, as well as write access to the reports schema and to all
tables in it.

The above example shows the general structure of the privileges section: the first keys
within it are the object types. pgbedrock currently supports schemas, sequences, and tables
as object types, each of which is optional to include. Within each object type, we have keys
for read and write, also both optional. Under each of these entries we have a list of the
items to grant to.

Note that the foo.\* syntax is not a regex expression but rather a shorthand for listing everything
in the schema. As a result, putting foo.bar\* (to get tables foo.barn or foo.barbados) won't work;
only foo.\* will work.

**owns**: dict (default: empty)
The objects that this role owns. At present only schema ownership is managed, which is supported by
providing the 'schemas' keyword followed by a list of schemas owned by this role (see the "What Is
pgbedrock?" section for an example). If a schema is intended to be a personal schema (i.e. named
the same as its owner and with all objects in the schema owned by that schema owner) then use
`has_personal_schema` instead.


### Password Management
Password management deserves some additional clarification. Since passwords shouldn't be stored in
plain text in version control, pgbedrock can use a provided environment variable to fill in a
password. For example, one could have a role defined as:
```
myrole:
    attributes:
        - PASSWORD "{{ env['MYROLE_PASSWORD'] }}"
```
Note that the environment variable can be named whatever you would like. As long as that variable
exists in the environment, pgbedrock will use it. If a variable is declared in the spec template
but does not exist in the environment, pgbedrock will refuse to run and will report the name of the
missing environment variable in its error message.

Note that if we are running pgbedrock through docker we will need to pass these environment
variables into our docker container. This can be done using the `-e` flag for docker run as shown
in the example for the "Running Via Docker" section above.


## Developing / Testing
Several functionalities exist for testing and debugging, as described below.


### Verbose Mode
To see all queries executed by pgbedrock as the executions happen, run pgbedrock with the
`--verbose` flag. Note that this will likely be a lot of output, so you may want to tee it into a
log file.


### Testing With pytest
To test locally, you'll need to get your Python environment set up. Assuming you already have
Python 3 and want to run pgbedrock inside a virtual environment, run:
```
mkvirtualenv pgbedrock3 --python python3
pip3 install -e . -r requirements-dev.txt
```

Next we need a local Postgres to test against. We will spin one up with:
```
make start_postgres
```

Now we are ready to test. We can run the test suite by simply typing `pytest`. Note that if you've
previously run the test suite with docker (as defined below) that you will need to run `make clean`
first to clear out pytest's cache or else pytest will error out.


### Testing With Docker
We can also test locally via docker. This has the advantage of letting us test our code in both
Python 2 and Python 3, though pgbedrock support for Python 2 may be dropped in the future. In any
case, testing via docker is quite simple; just run:
```
make test
```

This will build two tester containers: one for Python 2.7 and one for Python 3.6, start up Postgres,
then run our test suite via pytest inside each tester container.


### Checking Code Coverage
Running `make coverage` will show code coverage.


## Releasing A New Version
Once your PR has been merged into master:
1. Increment the __version__ in the pgbedrock/__init__.py file and commit that change.
2. Push a new git tag to the repo by doing:
    * Write the tag message in a dummy file called `tag_message`. We do this to allow multi-line tag
      messages
    * `git tag x.x.x -F tag_message`
    * `git push --tags origin master`
2. Run `make release-pypi`.
3. Run `make release-quay`. This may require doing a docker login to quay first.


## License
Copyright 2018 Squarespace, Inc.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
in compliance with the License. You may obtain a copy of the License at:

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License
is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied. See the License for the specific language governing permissions and limitations under
the License.
