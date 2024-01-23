#/bin/bash
# Purpose:  Use to set up environment to compile and run examples if ESAPI
#           downloaded from an Svn or Git repository.
# Usage:    From csh, tcsh:
#               $ source ./setenv-git.sh
#           From most other *nix shells:
#               $ . ./setenv-git.sh
#
#           where '$' represents the shell command line prompt.
###########################################################################

esapi_resources="$(\cd ../../../configuration/esapi >&- 2>&- && pwd)"
esapi_resources_test="$(\cd ../../../src/test/resources/esapi >&- 2>&- && pwd)"


# IMPORTANT NOTE:  These dependency versions may need updated. Should match
#                  what is in ESAPI's pom.xml.
esapi_classpath=".:\
../../../target/classes:\
$(ls ../../../target/esapi-*.jar 2>&- || echo .):\
$(./findjar.sh commons-fileupload-1.5.jar):\
$(./findjar.sh servlet-api-2.4.jar)"

if [[ ! -r "$esapi_resources"/ESAPI.properties ]]
then echo >&2 "setenv-git.sh: Can't read ESAPI.properties in $esapi_resources"
     return 1   # Don't use 'exit' here or it will kill their current shell.
fi

if [[ ! -r "$esapi_resources_test"/ESAPI.properties ]]
then echo >&2 "setenv-git.sh: Can't read ESAPI.properties in $esapi_resources_test"
     return 1   # Don't use 'exit' here or it will kill their current shell.
fi

echo ############################################################
echo "esapi_resources=$esapi_resources"
echo "esapi_resources_test=$esapi_resources_test"
echo "esapi_classpath=$esapi_classpath"
echo ############################################################

export esapi_classpath esapi_resources esapi_resources_test
