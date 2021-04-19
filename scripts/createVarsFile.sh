#!/bin/bash
# Purpose: Answer some questions and provide a new 'vars.<version>' from 'vars.template' to use for creating release notes.

prog="${0##*/}"

function iprompt    # prompt_message
{
    typeset ANS
    read -p "$@ (y|n): " ANS
    case "$ANS" in
    [Yy]|[Yy][Ee][Ss])  return 0    ;;
    *)  return 1    ;;
    esac
}

read -p "Enter release # for NEW ESAPI version you are doing release notes for: " VERSION
if [[ -f "vars.$VERSION" ]]
then
    iprompt "File 'vars.$VERSION' already exists. Continuing will overwrite it.  Continue?" || exit 1
fi


read -p "Enter release # for the PREVIOUS ESAPI version: " PREV_VERSION
read -p "Enter (planned) release date of NEW / current version you are preparing in YYYY-MM-DD format: " YYYY_MM_DD_RELEASE_DATE
read -p "Enter release date of PREVIOUS ESAPI version in YYYY-MM-DD format: " PREV_RELEASE_DATE

echo You entered:
echo =================================================
echo VERSION=$VERSION
echo PREV_VERSION=$PREV_VERSION
echo YYYY_MM_DD_RELEASE_DATE=$YYYY_MM_DD_RELEASE_DATE
echo PREV_RELEASE_DATE=$PREV_RELEASE_DATE
echo =================================================
echo

if iprompt "Are ALL your previous answers correct?"
then
    # Create the new    vars.${VERSION} file based on vars.template
    sed -e "s/^VERSION/VERSION=$VERSION/" \
        -e "s/^PREV_VERSION/PREV_VERSION=$PREV_VERSION/" \
        -e "s/^YYYY_MM_DD_RELEASE_DATE/YYYY_MM_DD_RELEASE_DATE=$YYYY_MM_DD_RELEASE_DATE/" \
        -e "s/^PREV_RELEASE_DATE/PREV_RELEASE_DATE=$PREV_RELEASE_DATE/" \
                vars.template > "vars.$VERSION"
else
    echo "$prog: Aborting. Rerun the script to correct your answers." >&2
    exit 1
fi
