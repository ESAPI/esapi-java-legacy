#!/bin/bash
# Purpose: Persist some encrypted data by saving it to a file. Shows how
#          the serialization works. See ../java/PersistedEncryptedData.java
#          for details.

classpath=".:../../../target/ESAPI-2.0.jar:\
$(./findjar.sh log4j-1.2.12.jar):\
$(./findjar.sh commons-fileupload-1.2.jar):\
$(./findjar.sh servlet-api-2.4.jar)"
cd ../java
set -x
java -Dlog4j.configuration=./src/test/resources/log4j.xml \
    -Dorg.owasp.esapi.resources="configuration/.esapi" \
    -ea -classpath "$classpath" \
    PersistedEncryptedData "$@"
