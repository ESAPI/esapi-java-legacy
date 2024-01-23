#!/bin/sh
# Purpose: Run an example class in ../java directory

if [[ -z "$esapi_classpath" ]]
then
    echo >&2 "esapi_classpath not set. Did you dot the appropriate env file?"
    echo >&2 "If you are using ESAPI from downloaded zip file, use:"
    echo >&2 "        . ./setenv-zip.sh"
    echo >&2 "If you are using ESAPI pulled from SVN repository, use:"
    echo >&2 "        . ./setenv-git.sh"
    exit 1
fi

cd ../java
className=${1%.class}
shift
if [[ ! -r ${className}.class ]]
then echo >2&1 "Can't find class file: ${className}.class"
     exit 1
fi
echo "Using your TEST version of ESAPI.properties file: ${esapi_resources_test:?}/ESAPI.properties"
echo
set -x
java -Dorg.owasp.esapi.resources="$esapi_resources_test" \
     -Djava.util.logging.config.file="$esapi_resources/esapi-java-logging.properties" \
     -classpath "$esapi_classpath" \
     ${className} "$@"
