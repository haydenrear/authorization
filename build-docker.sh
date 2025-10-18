#!/usr/bin/env bash

./gradlew clean
./gradlew buildDocker -Penable-docker=true -Pbuild-authorization-server=true