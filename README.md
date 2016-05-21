Enterprise Security API for Java (Legacy)
=================

[![Build Status](https://travis-ci.org/bkimminich/esapi-java-legacy.svg?branch=master)](https://travis-ci.org/bkimminich/esapi-java-legacy)
[![Coverage Status](https://coveralls.io/repos/github/bkimminich/esapi-java-legacy/badge.svg?branch=develop)](https://coveralls.io/github/bkimminich/esapi-java-legacy?branch=develop)
[![Coverity Status](https://scan.coverity.com/projects/8517/badge.svg)](https://scan.coverity.com/projects/bkimminich-esapi-java-legacy)

<table border=0>
<tr>
<td>
OWASP ESAPI (The OWASP Enterprise Security API) is a free, open source, web application security control library that makes it easier for programmers to write lower-risk applications. The ESAPI for Java library is designed to make it easier for programmers to retrofit security into existing applications. ESAPI for Java also serves as a solid foundation for new development.
</td>
</tr>
</table>

# What does Legacy mean?
<p>This is the legacy branch of ESAPI which means it is an actively maintained branch of the project, however feature development for this branch will not be done. Features that have already been scheduled for the 2.x branch will move forward, but the main focus will be working on the ESAPI 3.x branch.

<b>IMPORTANT NOTE:</b>
The default branch for ESAPI legacy is now the 'develop' branch (rather than the 'master' branch), where future development, bug fixes, etc. will now be done. The 'master' branch is now marked as "protected"; it reflects the latest stable ESAPI release (2.1.0.1 as of this date). Note that this change of making the 'develop' branch the default may affect any pull requests that you were intending to make.

# Where can I find ESAPI 3.x?
https://github.com/ESAPI/esapi-java

# Contributing to ESAPI legacy
## How can I contribute or help with fix bugs?
Fork and submit a pull request! Simple as pi! We generally only accept bug fixes, not new features because as a legacy project, we don't intend on adding new features, although we may make exceptions. If you wish to propose a new feature, the best place to discuss it is via the ESAPI-DEV mailing list mentioned below. Note that we vet all pull requests, including coding style of any contributions; use the same coding style found in the files you are already editing.

### What happened to Google code?
In mid-2014 ESAPI Migrated all code to GitHub. This migration was completed in November 2014.

### What about the issues still located on Google Code?
All issues from Google Code have been migrated to GitHub issues. We have a JIRA/Confluence instance allocated to us, but it has not be configured to synchronize with the GitHub issues, and thus is should not be used. JIRA is fine, but if we can't have it synchronized with GitHub issues (which is where the majority of our users report issues), it is not usuable. As developers, we do not want to spent time having to close issues from multiple bug-tracking sites. Therefore, until this synchronization happens (see GitHub issue #371), please ONLY use GitHub for reporting bugs.

### Find an Issue?
If you have found a bug, then create an issue on the esapi-legacy-java repo: https://github.com/ESAPI/esapi-java-legacy/issues

### Find a Vulnerability?
If you have found a vulnerability in ESAPI legacy, first search the issues list (see above) to see if it has already been reported. If it has not, then please contact both Kevin W. Wall (kevin.w.wall at gmail.com) and Chris Schmidt (chris.schmidt at owasp.org) directly. Please do not report vulnerabilities via GitHub issues or via the ESAPI mailing lists as we wish to keep our users secure while a patch is implemented and deployed. If you wish to be acknowledged for finding the vulnerability, then please follow this process. (Eventually, we would like to have BugCrowd handle this, but that's still a ways off.) Also, when you post the email describing the vulnerability, please do so from an email address that you usually monitor.

## Where to Find More Information on ESAPI

*Wiki:* https://www.owasp.org/index.php/Category:OWASP_Enterprise_Security_API

*Nightly Build:* Travis CI - https://travis-ci.org/bkimminich/esapi-java-legacy

~~JIRA: https://owasp-esapi.atlassian.net/browse/ESAPILEG~~<br />Issues: Until further notice, use the GitHub issues for reporting bugs and enhancement requests.


*Documentation:* https://owasp-esapi.atlassian.net/wiki/display/ESAPILEG/ESAPI+Legacy (Coming Soon), for now find general documentation under the 'documentation/' directory, and the latest Javadoc under https://www.javadoc.io/doc/org.owasp.esapi/esapi/

*Realtime Support available on our IRC Channel:*<br/>
Server: irc.freenode.net<br/>
Channel: #esapi<br/>
Webchat http://webchat.freenode.net/

*Mailing lists:*
[ESAPI-Users mailing list](https://lists.owasp.org/mailman/listinfo/esapi-user/) and
[ESAPI-Developers mailing list](https://lists.owasp.org/mailman/listinfo/esapi-dev/)
