#!/bin/sh

if [ -z "$esapi_classpath" ]
then
    echo >&2 "esapi_classpath not set. Did you dot the appropriate env file?"
    echo >&2 "If you are using ESAPI from downloaded zip file, use:"
    echo >&2 "        . ./setenv-zip.sh"
    echo >&2 "If you are using ESAPI pulled from Git or Svn repository, use:"
    echo >&2 "        . ./setenv-git.sh"
    exit 1
fi

cd ../java
echo "This will generate the properties Encryptor.MasterKey and Encryptor.MasterSalt"
echo "which you will have to paste into your production ESAPI.properties file."
echo
echo "Do NOT copy those properties from your TEST ESAPI.properties as they are"
echo "the same for everyone and therefore are not secret."
echo
echo "Your PRODUCTION version of ESAPI.properties file: $esapi_resources/ESAPI.properties"
echo "Hit <Enter> to continue..."; read GO
echo
set -x
# This should use the real ESAPI.properties in $esapi_resources that does
# not yet have Encryptor.MasterKey and Encryptor.MasterSalt yet set.
java -Dorg.owasp.esapi.resources="$esapi_resources" \
     -Djava.util.logging.config.file="$esapi_resources/esapi-java-logging.properties" \
     -classpath "$esapi_classpath" \
     org.owasp.esapi.reference.crypto.JavaEncryptor "$@"
