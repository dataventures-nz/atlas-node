#!/usr/bin/env bash
docker build -t dataventures/atlas-node .
docker run --env-file ../.env -p 3000:3000 -it dataventures/atlas-node
