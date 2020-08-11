#!/bin/bash

cd "${0%/*}"

#This is just an example and assumes you have

#to debug remotely replace localhost with *
OPTS="-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=localhost:8187"

#adjust paths to tsunami binaries
CLASSPATH="../lib/*"

CONFIGFILE="../conf/tsunami.yaml"

java "$OPTS" -cp "$CLASSPATH" \
	-Dtsunami-config.location="$CONFIGFILE" com.google.tsunami.main.cli.TsunamiCli "$@" 
