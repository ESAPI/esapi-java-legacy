#!/bin/bash
# Purpose: Persist some encrypted data by saving it to a file. Shows how
#          the serialization works. See ../java/PersistedEncryptedData.java
#          for details.
# Usage: ./persistEncryptedData.sh plaintext_string output_file {hex|base64|raw}
#           The last argument refers to how the encrypted data will be encoded.
#           The output file name will also be named with this as the file
#           suffix.
##############################################################################

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
# Since this is just an illustration, we will use the test ESAPI.properties in
# $esapi_resources_test. That way, it won't matter if the user has neglected
# to run the 'setMasterKey.sh' example before running this one.
echo "Using your TEST version of ESAPI.properties file: $esapi_resources_test/ESAPI.properties"
set -x
java -Dorg.owasp.esapi.resources="$esapi_resources_test" \
     -Djava.util.logging.config.file="$esapi_resources/esapi-java-logging.properties" \
     -ea -classpath "$esapi_classpath" \
     PersistedEncryptedData "$@"
