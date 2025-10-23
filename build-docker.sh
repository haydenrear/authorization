#!/usr/bin/env bash

./gradlew clean
./gradlew pushImages -Penable-docker=true -Pbuild-authorization-server=true