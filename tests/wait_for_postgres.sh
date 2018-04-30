#!/usr/bin/env bash
PG_ISREADY=/usr/lib/postgresql/9.6/bin/pg_isready
ISREADY="$PG_ISREADY --host=$POSTGRES_HOST"
$ISREADY
while [[ $? -ne 0 ]]; do
    sleep 1
    echo "waiting on Postgres"
    $ISREADY
done
