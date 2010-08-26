#!/bin/sh
# Purpose: Prepare an ESAPI release.
#
# Usage: esapi-release.sh esapi_svn_dir
#   where,  esapi_svn_dir   is the directory where you retrieved the ESAPI
#                           SVN tree to and built ESAPI via Maven or Eclipse.
#                           This directory _must_ already exist.
#                           There should be a 'src' and 'target' directories
#                           under this directory and the 'target' directory
#                           is where we will build the ESAPI zip file that
#                           you then will be placed into the owasp-esapi-java
#                           project hosting on Google Code.
#
# Assumptions:  Maven (mvn) is available in $PATH. If not, modify PATH
#               in script (see 'Tunable Parameters') accordingly.
#
#               The correct version has been set / updated in pom.xml for
#               the 'esapi' <artifactId> and this has been committed to SVN.
#
#               All tests pass. We skip the running of all the JUnit tests.
#               (See the call to mvn and the -Dmaven.test.skip=true argument.)
#
# Bugs: This is going to be a bitch to write as a DOS .bat script. I should
#       have my head examined for termites! What *was* I thinking???
#
#       Need to figure out how to create changelog.txt using 'svn log' command.
#
#############################################################################
#
# This file is part of the Open Web Application Security Project (OWASP)
# Enterprise Security API (ESAPI) project. For details, please see
# http://www.owasp.org/index.php/ESAPI.
#
# Copyright (c) 2010 - The OWASP Foundation
#
# ESAPI is published by OWASP under the BSD license. You should read and
# accept the LICENSE before you use, modify, and/or redistribute this software.
#
# Author: kevin.w.wall@gmail.com
############################################################################

#
# Tunable parameters
#
#PATH=$PATH:/path/to/maven
zipcmd=zip          # Is there something better for Linux?
                    # This doesn't seem to have very good compression.
unzipcmd=unzip
# clean=clean         # Comment out if you don't Maven to do 'clean'. Will speed
                    # things up a little bit.

#
# Non-tunable parameters
#
PROG="${0##*/}"
USAGE="Usage: $PROG esapi_svn_dir"

# Cause the 'echo' builtin to interpret backslash-escaped characters.
# If KornShell is installed as /bin/sh, this command won't be available,
# but for it, 'echo' already works the way we want it to anyhow.
shopt -s xpg_echo 2>/dev/null

if [[ $# -eq 1 ]]
then
    esapi_svn_dir="$1"
else
    echo >&2 "$USAGE"
    # Note: exit code '2' is standard for a simple usage error, w/ no other
    #       error message. Unfortunaely, no one (at least the GNU folks)
    #       seem to follow this convention any longer and all use 1. We're
    #       sticking with old school, 'cuz I'm an old guy. ;-)
    exit 2
fi

# A few simple directory sanity checks.
[[ $esapi_svn_dir == $esapi_release_dir ]] &&
    { echo >&2 "$PROG: Directory names must be different.\n$USAGE"; exit 1; }
[[ ! -d $esapi_svn_dir ]] &&
    { echo >&2 "$PROG: ESAPI SVN directory, $esapi_svn_dir, does not exist or not a directory."; exit 1; }
[[ ! -d $esapi_svn_dir/src/main ]] &&
    { echo >&2 "$PROG: Wrong directory specified??? Missing 'src/main' directory: $esapi_svn_dir/src/main - does not exist or not a directory."; exit 1; }
[[ -f "$esapi_svn_dir"/pom.xml ]] ||
    { echo 2>&1 "$PROG: missing pom.xml. Looks like $esapi_svn_dir is not the SVN dir.";
      echo 2>&1 "USAGE"; exit 1; }

tmpdir=/tmp/$PROG.$RANDOM-$$
mkdir $tmpdir || exit 1 # Exit if it already exists.
trap "rm -fr $tmpdir" EXIT  # We probably want this skipped if the mkdir fails
umask 022
esapi_release_dir=$tmpdir/esapi_release_dir
mkdir $tmpdir/esapi_release_dir || exit 1

# Create an intermediate distribution zip file. The zip file will be
# left in the 'target' directory and named according to what <version>
# is in the pom.xml file for the 'esapi' <artifactId>. For release
# candidates, it will be something like this:
#       esapi-2.0_RC7-SNAPSHOT-dist.zip
# and inside of it, the ESAPI jar would be named 'esapi-2.0_RC7-SNAPSHOT.jar'.
cd "$esapi_svn_dir"
tmpout=$tmpdir/mvn.out
echo "Running mvn to create intermediate zip file.\nPlease wait; this probably will take awhile..."
rm -f target/esapi-*.zip target/esapi-*.jar
mvn $clean site -Pdist -Dmaven.test.skip=true >$tmpout 2>&1
if [[ $? != 0 ]]
then    echo >&2 "$PROG: Maven failed to build distribution zip file"
        echo >&2 "\tSee results in: $tmpout"
        trap - EXIT    # Clear exit trap so stuff not removed.
        exit 1
else    rm $tmpout
        echo "Maven completed successfully."
fi

jarfile=$(ls target/esapi-*.jar 2>&-)
if [[ -n "$jarfile" && -r $jarfile ]]
then    jarfile=$PWD/$jarfile
else    echo >&2 "$PROG: Can't find ESAPI jar file created by Maven."
        exit 1
fi
# OK, now we need to adjust the jar file. We don't want the properties in
# the ESAPI jar as too many people have complained about the ESAPI.properties
# and other stuff there.
jartmpdir=$tmpdir/esapi-jar
mkdir $jartmpdir
cd $jartmpdir || exit
jar xf "$jarfile"
rm -fr .esapi
rm -f properties/* log4j.*
# TODO: This part would need some work if we sign or seal the ESAPI jar as
#       that creates a special MANIFEST.MF file and other special files and
#       it's not clear they will be merely copied by the simply jar command
#       below.
jar cf "$jarfile" .

# Now work on the zip file.
cd "$esapi_svn_dir"
zipfile=$(ls target/esapi-*.zip 2>&-)
if [[ -n "$zipfile" && -r $zipfile ]]
then    zipfile="$esapi_svn_dir"/$zipfile   # 'target/' already included.
else    echo >&2 "$PROG: Can't find ESAPI zip file created by Maven."
        exit 1
fi
[[ -s $zipfile ]] ||
    { echo 2>&1 "$PROG: zip file $zipfile has 0 size."; exit 1; }
$unzipcmd -q "$zipfile" -d "$esapi_release_dir" || exit 1
cd "$esapi_release_dir" || exit 1

# 1) Combine the two license files into one and make it a DOS .txt
#    file so those do don't have real editors (i.e., notepad newbs) can
#    read it just by clicking on it. Generally reading DOS text files on *nix
#    is never a problem.
( echo "\t\tESAPI Source Code:\n\n"; cat LICENSE; echo "\n\n=========================\n\n\t\tESAPI Documentation:\n\n"; cat LICENSE-CONTENT ) >LICENSE.txt
rm LICENSE LICENSE-CONTENT
unix2dos -q LICENSE.txt

# 2) Patch up the 'configuration' directory. Need to copy owasp-esapi-dev.jks
#    here as well as the .esapi directory. Also need to populate the
#    properties subdirectory.
cp -p "$esapi_svn_dir"/resources/owasp-esapi-dev.jks configuration/
cp -r -p "$esapi_svn_dir"/src/main/resources/.esapi configuration/.esapi/
cp -p "$esapi_svn_dir"/src/main/resources/properties/* configuration/properties/

# 3) Create the changelog.txt which should be the changes since the
#    last release.
##TODO  - Not sure how to do this, but their must be a way since the Subclipse
#         Eclipse plugin is able to do it somehow. We can use 'svn log' if
#         we can figure out the starting and ending SVN revisions. (See
#         http://www.bernzilla.com/item.php?id=613 for details.)
echo "$PROG: Skipping creation of changelog.txt in zip file."
echo "\tManually create changelog.txt and add it to the final zip file."

# 4) Update zip file w/ new, updated ESAPI jar file.
cp -p "$jarfile" .

# 5) Fix up permissions so when zip is extracted, it comes out sane.
chmod -R a+r,go-w .

# Now we take the contents of the ESAPI release directory and re-zip it.
# We can't use the 'freshen' option here because that has to be run
# from the same directory (which would be the ESAPI SVN directory).
rm "$zipfile"
cd "$esapi_release_dir"
$zipcmd -q -r $zipfile .

cd /    # In case some weird 'rm' command (from EXIT trap) prevents us from
        # removing directory that we are under. I could see something like
        # that happen with Cygwin and Windows.
echo "Zip file at: $zipfile\nPlease check it for accuracy before releasing."
exit 0
