Project Goals
=============

pgbedrock was created with several goals in mind:

#. **Simplify permission complexity.**
     pgbedrock simplifies object access down to read vs. write.  As a result, an administrator
     doesn't need to know that within Postgres 'read' access is really ``SELECT`` for tables but
     ``USAGE`` for schemas, or that write access for schemas means ``CREATE`` but for tables it is a
     combination of ``INSERT``, ``UPDATE``, ``DELETE``, ``TRUNCATE``, ``REFERENCES``, and
     ``TRIGGER``.

#. **Co-locate all config.**
     Within Postgres itself, role, role membership, ownership, and permission information is
     distributed across a variety of locations: ``pg_authid``, ``pg_class``, ``pg_namespace``,
     ``pg_default_acl``, and so on. As a result, it is hard to get a high-level "lay of the land".
     pgbedrock puts all this config into one YAML file so it's easy to stay on top of how the
     database is configured.

#. **Assert that config matches reality.**
     Because information is so distributed in a normal Postgres cluster, it is easy for things to
     get out of sync. pgbedrock checks the YAML spec against the provided database and asserts that
     the two match. If they do not, it makes changes to the database to make them match,
     transparently reporting all of the queries that it ran to make those changes.

#. **Provide an auditable log of changes.**
     By using a YAML spec, our config can be put into source control, allowing us to see who had
     access at any given time. In addition, each time pgbedrock runs it will output the set of SQL
     queries that it ran to bring the cluster in line with the spec. By storing those outputs an
     administrator will have an audit trail of when each change occurred.

As a knock-on benefit, by having pgbedrock run on a schedule one can enforce that config changes be
put into code and through a PR process: changes made live to a cluster will be revoked the next
time the tool runs, helping dissuade administrators from continually making live, unaudited changes.
