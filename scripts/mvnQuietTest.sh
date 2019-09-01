#!/bin/bash
# Purpose: Run      'mvn test'      with system property
#                       'org.owasp.esapi.logSpecial.discard'
#          set to true, so that all of the logSpecial output is suppressed.
#          This reduces the total output of 'mvn test' by about 2000 or so
#          lines.

exec mvn -Dorg.owasp.esapi.logSpecial.discard=true test $@
