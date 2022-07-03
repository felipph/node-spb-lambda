#!/bin/bash
cd lambda-spb-ts-src
npm run build
cd ..
docker compose up