#!/usr/bin/env bash
if [[ $(echo "$POSTGRES_VERSION" | cut -d '.' -f 1) == 10 ]]; then
    # Postgres 10 versions are only x.x instead of x.x.x, so the short version is just "10"
    POSTGRES_SHORT_VERSION="10";
else
    POSTGRES_SHORT_VERSION=$(echo "$POSTGRES_VERSION" | cut -d '.' -f 1,2);
fi

ISREADY="pg_isready --host=$POSTGRES_HOST"
$ISREADY
while [[ $? -ne 0 ]]; do
    sleep 1
    echo "waiting on Postgres"
    $ISREADY
done
