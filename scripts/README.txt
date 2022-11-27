This directory is for utilities used for building / packaging / releasing ESAPI.

========================

README.txt          -- This readme file.
esapi-release.sh    -- Obsolete script to create new ESAPI release. Will be replaced soon. Do not use for now.
mvnQuietTest.bat    -- Run 'mvn test' from DOS cmd prompt with logSpecial output suppressed.
mvnQuietTest.sh     -- Run 'mvn test' from bash with logSpecial output suppressed.
createVarsFile.sh   -- Bash script to create a vars.2.x.y.z file that is 'sourced' by the 'newReleaseNotes.sh' script.
esapi4java-core-TEMPLATE-release-notes.txt - Basic template used to create the new release notes file.
newReleaseNotes.sh  -- Bash script to create the release notes boillerplate from the provided release argument and the TEMPLATE file.
vars.2.?.?.?        -- File that is 'sourced' (as in "source ./filename") and used with newReleaseNotes.sh
                       and is associated with the release number associated with the file name.
vars.template       -- Template to construct the release specific vars files
