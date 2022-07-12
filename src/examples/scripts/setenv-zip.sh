#!/bin/bash
# Purpose:  Use to set up environment to compile and run examples if ESAPI
#           downloaded as a zip file.
# Usage:    From csh, tcsh:
#               $ source ./setenv-zip.sh
#           From most other *nix shells:
#               $ . ./setenv-zip.sh
#
#           where '$' represents the shell command line prompt.
###########################################################################

# Here we don't look for the specific versions of the dependent libraries
# since the specific version of the library is delivered as part of the
# ESAPI zip file. In this manner, we do not have to update this if these
# versions change.
esapi_classpath=".:\
$(ls ../../../esapi*.jar):\
$(./findjar.sh -start ../../../libs commons-fileupload-*.jar):\
$(./findjar.sh -start ../../../libs servlet-api-*.jar)"

esapi_resources="$(\cd ../../../configuration/esapi >&- 2>&- && pwd)"
esapi_resources_test="$(\cd ../../../src/test/resources/esapi >&- 2>&- && pwd)"


if [[ ! -r "$esapi_resources"/ESAPI.properties ]]
then echo 2>&1 "setenv-svn.sh: Can't read ESAPI.properties in $esapi_resources"
     return 1   # Don't use 'exit' here or it will kill their current shell.
fi

if [[ ! -r "$esapi_resources_test"/ESAPI.properties ]]
then echo 2>&1 "setenv-svn.sh: Can't read ESAPI.properties in $esapi_resources_test"
     return 1   # Don't use 'exit' here or it will kill their current shell.
fi


echo ############################################################
echo "esapi_resources=$esapi_resources"
echo "esapi_resources_test=$esapi_resources_test"
echo "esapi_classpath=$esapi_classpath"
echo ############################################################

export esapi_classpath esapi_resources esapi_resources_test
