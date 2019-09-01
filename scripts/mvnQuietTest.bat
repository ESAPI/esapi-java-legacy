@ECHO off
rem Purpose: Run      'mvn test'      with system property
rem                       'org.owasp.esapi.logSpecial.discard'
rem          set to true, so that all of the logSpecial output is suppressed.
rem          This reduces the total output of 'mvn test' by about 2000 or so
rem          lines.

mvn -Dorg.owasp.esapi.logSpecial.discard=true test %*
