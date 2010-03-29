#!/bin/sh

findjar=$PWD/findjar.sh

cd ../../../
esapi_props=

if [[ -f configuration/.esapi/ESAPI.properties ]]
then    esapi_props="configuration/.esapi/ESAPI.properties"
else    esapi_props="src/main/resources/.esapi/ESAPI.properties"
fi
if [[ ! -r $esapi_props ]]
then    echo "$0: ESAPI.properties file ($esapi_props) not readable." >&2
        exit 1
fi

# This classpath is relative to ../../.. directory (from here). See above 'cd'
classpath=".:target/ESAPI-2.0.jar:\
$($findjar log4j-1.2.12.jar):\
$($findjar commons-fileupload-1.2.jar):\
$($findjar servlet-api-2.4.jar)"

set -x
java -Dlog4j.configuration=src/test/resources/log4j.xml \
     -Dorg.owasp.esapi.resources=$(dirname $esapi_props) \
     -classpath $classpath \
     org.owasp.esapi.reference.crypto.JavaEncryptor "$@"
