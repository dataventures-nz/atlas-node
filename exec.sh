#!/usr/bin/env bash
docker build -t dataventures/atlas-node .
docker run --env-file ../.env -p 3010:3010 -it dataventures/atlas-node
