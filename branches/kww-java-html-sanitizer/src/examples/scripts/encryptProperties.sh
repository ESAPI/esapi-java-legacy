#!/bin/bash
# Create or display encrypted properties.
#
# Usage: encryptedProperties.sh {-display|-create} [encrypted_properties_filename]
#        You can use the file 'encrypted.properties' in this directory
#        as a sample if you so wish. That's what it defaults to.

USAGE="Usage: encryptedProperties.sh {-display|-create} [encrypted_properties_filename]"

if [[ -z "$esapi_classpath" ]]
then
    echo 2>&1 "esapi_classpath not set. Did you dot the appropriate env file?"
    echo 2>&1 "If you are using ESAPI from downloaded zip file, use:"
    echo 2>&1 "        . ./setenv-zip.sh"
    echo 2>&1 "If you are using ESAPI pulled from SVN repository, use:"
    echo 2>&1 "        . ./setenv-svn.sh"
    exit 1
fi

case $1 in
-display|-create)   action="$1" ;;
*)  echo "Missing '-display' or '-create' arg."; echo $USAGE; exit 2    ;;
esac

filename=${2:-encrypted.properties}
case "$filename" in
/*) ;;
*)   filename="$PWD/$filename"    ;;
esac

if [[ -f "$filename" && "$action" == "-create" ]]
then    echo "Output file '$filename' already exists; will not overwrite."
        echo "Remove manually if you want it overwritten."
        exit 1
elif [[ -f "$filename" && "$action" == "-display" ]]
then
    [[ ! -s "$filename" ]] && { echo "file has zero size"; exit 1; }
else    # File doesn't exist, so try to create it to see if we can write it.
        > "$filename" || exit 1
fi

cd ../java
# Here, we want to use the ESAPI.properties in $esapi_resources_test since
# we know the Encryptor.MasterKey that it was encrypted with and we need
# to decrypt with the same one. The one in $esapi_resources doesn't have
# one set by default, and if 'setMasterKey.sh' is called first to create
# that property, it will differ what was used in the 'encrypted.properties'
# file.
if [[ "$action" == "-display" ]]
then
    set -x
    java -Dlog4j.configuration="file:$log4j_properties" \
         -Dorg.owasp.esapi.resources="$esapi_resources_test" \
         -classpath "$esapi_classpath" \
         DisplayEncryptedProperties "$filename"
else
    echo
    echo ======================= Instructions ======================
    echo "When you see 'Enter key: ', enter the property name."
    echo "When you see 'Enter value: ', enter the property value."
    echo "The property value will be encrypted and the value will be in plaintext"
    echo "and they will be placed in the specified output file."
    echo "End entering key/value pairs by entering an empty key & value."
    echo ===========================================================
    echo
    echo "Hit <Enter> to continue..."; read GO
    set -x
    java -Dlog4j.configuration="file:$log4j_properties" \
         -Dorg.owasp.esapi.resources="$esapi_resources_test" \
         -classpath "$esapi_classpath" \
      org.owasp.esapi.reference.crypto.DefaultEncryptedProperties "$filename" &&
      echo "Output of encrypted properties in file: $filename"
fi
