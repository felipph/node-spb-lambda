#!/bin/bash
cd lambda-spb-src
npm install
zip -r function.zip .

docker compose up