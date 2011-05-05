#!/bin/sh

if [[ -z "$esapi_classpath" ]]
then
    echo 2>&1 "esapi_classpath not set. Did you dot the appropriate env file?"
    echo 2>&1 "If you are using ESAPI from downloaded zip file, use:"
    echo 2>&1 "        . ./setenv-zip.sh"
    echo 2>&1 "If you are using ESAPI pulled from SVN repository, use:"
    echo 2>&1 "        . ./setenv-svn.sh"
    exit 1
fi
cd ../java
set -x
javac -classpath "$esapi_classpath" ${1:-*.java}
