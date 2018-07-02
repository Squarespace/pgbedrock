Notable Functionality And Caveats
=================================

* Only Postgres 9.5, 9.6, and 10 are currently supported
    Support for older Postgres versions is unlikely to be prioritized.

* pgbedrock will not delete or alter any objects
    pgbedrock is explicitly written to not do anything destructive toward the objects in the
    database. A revoked permission can simply be re-granted, but a table/schema/sequence that has
    been deleted is gone for good (unless you have backups). As a result, pgbedrock will not delete
    any objects, including roles, schemas, tables, and sequences. pgbedrock will configure these
    objects, but if they need to be deleted you will have to do that manually. If one of these
    objects is not listed in the spec.yml file then pgbedrock will refuse to run, alerting the user
    of the discrepancy and asking them to manually take action (i.e.  delete the role / schema /
    table / sequence or add it to the spec).

* Ownership and privilege management currently supports only schemas, tables, and sequences
    Support for managing ownership and privileges of other objects (for example: functions, foreign
    data wrappers, foreign servers, etc.) is not avaiable but may be added in the future.

* Roles and memberships are cluster-wide in Postgres
    This means that if you have multiple databases within one Postgres instance, all of those
    databases share the same roles and role memberships. The consequence of this is that if you use
    pgbedrock to manage all of those databases, then you will need to list the roles and role
    memberships in each database's spec file.

* pgbedrock simplifies permissions down to read vs. write
    In our experience, this is easier to reason about, easier to remember, and is a sufficient level
    of granularity for most use cases.  However, a consequence of this is that if you *do* use more
    fine-grained controls in your database then you will need to be more permissive or restrictive
    in your permissions in order to use pgbedrock (or, even better, put in a pull request to add
    support for finer-grained controls to pgbedrock!). As a concrete example, if roleA currently has
    ``INSERT`` permission to a table, then to use pgbedrock you will have to decide whether they
    will get read access (and thus lose that ``INSERT`` permission) or write access (and thus get
    ``UPDATE``, ``DELETE``, etc. permissions as well). If the spec is created with ``pgbedrock
    generate``, pgbedrock will take the latter approach (i.e. granting additional write-level
    access), so make sure to check the initial spec after generating it to verify that any changes
    it introduces are acceptable.

* Default privileges are granted for permissions like ``myschema.*``
    When a permission grant looks like ``myschema.*``, pgbedrock interprets that to mean "grant this
    permission for all existing tables *and for all future tables too*" (i.e. a default privilege).
    However, default privileges in Postgres are only applied to new tables created by the role that
    granted the privilege, meaning that if roleA grants default ``SELECT`` privileges on tables to
    roleB, then those default privileges will apply if and only if roleA is the one who creates a
    subsequent table. If instead roleC creates a table then the default privileges won't happen. To
    deal with this, when pgbedrock sees ``myschema.*`` it will identify all roles that have the
    ability to create objects in that schema and grant default privileges from each of these roles
    to the role that should have the default privileges.

* personal_schemas are supported
    It is common to give users a "sandbox" where they can create objects, modify them, delete them,
    etc.  A typical way to do this is to create a schema with the same name as the role and let them
    own it, i.e. the role ``jdoe`` would own the schema ``jdoe``.  Every object in the ``jdoe``
    schema should thus be owned by ``jdoe``. pgbedrock supports this concept in a few ways. First,
    by specifying ``has_personal_schema: yes`` for a role, a personal schema will be created if it
    does not exist. If the schema already exists, pgbedrock will make sure that the schema and all
    objects in it that pgbedrock manages are owned by this role, making changes to ownership to make
    this true. Finally, ``personal_schemas`` can be used as a special term in privilege grants. For
    example, a role can be given read-level table privileges to ``personal_schemas.*``, which will
    let that role read all tables in all personal schemas in the database. To be a personal schema,
    the schema must be owned by a role with the same name as the schema and that role must be able
    to login.
