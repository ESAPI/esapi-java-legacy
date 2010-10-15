#/bin/bash
# Purpose:  Use to set up environment to compile and run examples if ESAPI
#           downloaded from the SVN repository.
# Usage:    From csh, tcsh:
#               $ source ./setenv-svn.sh
#           From most other *nix shells:
#               $ . ./setenv-svn.sh
#
#           where '$' represents the shell command line prompt.
###########################################################################

# IMPORTANT NOTE:  Since you may have multiple (say) log4j jars under
#                  your Maven2 repository under $HOME/.m2/respository, we
#                  look for the specific versions that ESAPI was using as of
#                  ESAPI 2.0_RC7 release on 2010/08/22. If these versions
#                  changed, they will have to be reflected here.
#
esapi_classpath=".:\
$(ls ../../../target/esapi-*.jar):\
$(./findjar.sh log4j-1.2.12.jar):\
$(./findjar.sh commons-fileupload-1.2.jar):\
$(./findjar.sh servlet-api-2.4.jar)"

esapi_resources="$(\cd ../../main/resources/.esapi >&- 2>&- && pwd)"
esapi_resources_test="$(\cd ../../test/resources/.esapi >&- 2>&- && pwd)"

log4j_properties="../../main/resources/log4j.xml"

if [[ ! -r "$esapi_resources"/ESAPI.properties ]]
then echo 2>&1 "setenv-svn.sh: Can't read ESAPI.properties in $esapi_resources"
     return 1   # Don't use 'exit' here or it will kill their current shell.
fi

if [[ ! -r "$esapi_resources_test"/ESAPI.properties ]]
then echo 2>&1 "setenv-svn.sh: Can't read ESAPI.properties in $esapi_resources_test"
     return 1   # Don't use 'exit' here or it will kill their current shell.
fi

if [[ ! -r "$log4j_properties" ]]
then echo 2>&1 "setenv-svn.sh: Can't read log4j.xml: $log4j_properties"
     return 1   # Don't use 'exit' here or it will kill their current shell.
fi

## echo "esapi_resources=$esapi_resources"
## echo "esapi_resources_test=$esapi_resources_test"
## echo "log4j_properties=$log4j_properties"
## echo "esapi_classpath=$esapi_classpath"

export esapi_classpath esapi_resources esapi_resources_test log4j_properties
