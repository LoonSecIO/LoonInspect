# syntax=docker/dockerfile:1

# The database half of the bundle, as an image instead of a bind mount.
#
# docker-compose can hand stock postgres the role-creation script by mounting
# ./initdb into /docker-entrypoint-initdb.d. ECS cannot: a Fargate task has no
# repository checkout to mount from, so anything the database needs at first
# boot has to travel inside the image. This bakes the script in and changes
# nothing else — same base, same entrypoint contract, same environment
# variables. Passwords in particular stay runtime configuration, never build
# args: a credential in a build arg is a credential in an image layer.
#
# Two things are deliberately absent:
#   - A HEALTHCHECK. Both real consumers restate it anyway — compose because
#     bare pg_isready reports ready during initdb's own temporary server, and
#     ECS because Fargate ignores image healthchecks entirely, so the app
#     container's dependsOn needs one declared in the task definition.
#   - An RDS story. A managed database never runs this image; there
#     /docker-entrypoint-initdb.d does not exist and the master user is not a
#     superuser. Run the SQL from initdb/10-app-role.sh by hand instead.
FROM postgres:17-alpine

# Runs once, against an empty data directory, before Postgres accepts outside
# connections — the same contract as the compose bind mount this replaces.
# Editing a script here therefore takes both a rebuild and an empty data
# volume to have any effect; an existing database never re-runs it.
COPY initdb/ /docker-entrypoint-initdb.d/
