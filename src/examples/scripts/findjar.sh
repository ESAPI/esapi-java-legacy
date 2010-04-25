#!/bin/bash
# Purpose: Find specified jar and provide full path name to it for use in
#          Java classpath.
#
############################################################################

USAGE="Usage: ${0##*/} [-start starting_dir] jar_pattern"
PROG=${0##*/}

#   Default starting directory is Maven2 repository under $HOME ...
starting_dir=$HOME/.m2/repository

case "$1" in
-start) shift; starting_dir="$1"; shift ;;
-\?)    echo "$USAGE" >&2; exit 2 ;;
-*)     echo "$PROG: Unknown option: $1; treating as a jar pattern." >&2 ;;
esac

jar_pattern="$1"
case "$jar_pattern" in
*.zip|*.jar)    ;;  # Suffix already present
"") echo "$PROG: Missing jar pattern.\n$USAGE" >&2; exit 2    ;;
*)  jar_pattern="${jar_pattern}*.jar"                   ;;
esac

# echo "Starting location: $starting_dir"   # DEBUG
# echo "Jar pattern: $jar_pattern"          # DEBUG
find "$starting_dir" -type f -name "$jar_pattern" -print |
    egrep -v 'javadoc|sources'
