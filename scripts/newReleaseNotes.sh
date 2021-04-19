#!/bin/bash
# Purpose: Provide an assistance towards writing new ESAPI release notes. Still a lot of manual editing though.
#
# Usage: ./newReleaseNotes.sh new_esapi_vers_#
#        Should be run from the 'scripts' directory.

prog=${0##*/}
template="esapi4java-core-TEMPLATE-release-notes.txt"

newVers=${1?Missing new ESAPI version number}

if [[ -r vars.${newVers} ]]
then    source vars.${newVers}
else    echo "$prog: Can't find vars.${newVers} to source. Did you forget to create it based on vars.template?" >&2
        echo "      Execute './createVarsFile.sh' from the 'scripts' directory to create vars.${newVers}." >&2
        exit 1
fi

hereDocBanner="__________@@@@@___@@@@@__________"
tmpfile="/tmp/relNotes.$$"
trap "rm $tmpfile" EXIT

if [[ -r $template ]]
then
        echo "#!/bin/bash"  > $tmpfile
        echo "source vars.${newVers}" >> $tmpfile
        echo "cat >esapi4java-core-${VERSION}-release-notes.txt <<${hereDocBanner}" >> $tmpfile
        cat $template >> $tmpfile
        echo "${hereDocBanner}" >> $tmpfile
        echo "ls -l esapi4java-core-${VERSION}-release-notes.txt" >> $tmpfile
        bash $tmpfile
else    echo "$prog: Can't find or read release notes template file $template" >&2
        exit 1
fi

echo
echo "Now move the file 'esapi4java-core-${VERSION}-release-notes.txt' to the 'documenation/' directory" 
echo "and finish editing it there. Be sure to remove all the instructional lines starting with @@@"
echo "before committing it to GitHub."
