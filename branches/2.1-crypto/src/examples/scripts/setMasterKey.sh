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
echo "Your ESAPI.properties file: $esapi_properties"
echo
# set -x
# This should use the real ESAPI.properties in $esapi_resources that does
# not yet have Encryptor.MasterKey and Encryptor.MasterSalt yet set.
java -Dlog4j.configuration="$log4j_properties" \
     -Dorg.owasp.esapi.resources="$esapi_resources" \
     -classpath "$esapi_classpath" \
     org.owasp.esapi.reference.crypto.JavaEncryptor "$@"
