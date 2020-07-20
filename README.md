Enterprise Security API for Java (Legacy)
=================

[![Build Status](https://travis-ci.org/bkimminich/esapi-java-legacy.svg?branch=master)](https://travis-ci.org/bkimminich/esapi-java-legacy)
[![Coverage Status](https://coveralls.io/repos/github/bkimminich/esapi-java-legacy/badge.svg?branch=develop)](https://coveralls.io/github/bkimminich/esapi-java-legacy?branch=develop)
[![Coverity Status](https://scan.coverity.com/projects/8517/badge.svg)](https://scan.coverity.com/projects/bkimminich-esapi-java-legacy)
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/137/badge)](https://bestpractices.coreinfrastructure.org/projects/137)

<table border=0>
<tr>
<td>
OWASP® ESAPI (The OWASP Enterprise Security API) is a free, open source, web application security control library that makes it easier for programmers to write lower-risk applications. The ESAPI for Java library is designed to make it easier for programmers to retrofit security into existing applications. ESAPI for Java also serves as a solid foundation for new development.
</td>
</tr>
</table>

# What does Legacy mean?
<p>This is the legacy branch of ESAPI which means it is an actively maintained branch of the project, however significan *new* feature development for this branch will *not* be done. Features that have already been scheduled for the 2.x branch will move forward.

<b>IMPORTANT NOTES:</b>
The default branch for ESAPI legacy is now the 'develop' branch (rather than the 'master' branch), where future development, bug fixes, etc. will now be done. The 'master' branch is now marked as "protected"; it reflects the latest stable ESAPI release (2.1.0.1 as of this date). Note that this change of making the 'develop' branch the default may affect any pull requests that you were intending to make.

Also, the <i>minimal</i> baseline Java version to use ESAPI is Java 7. (This was changed from Java 6 during the 2.2.0.0 release.)

# Where can I find ESAPI 3.x?
https://github.com/ESAPI/esapi-java

Note however that work on ESAPI 3 has not yet become in earnest and is only in its earliest planning stages. Even the code that is presently there will likely change.

# Locating ESAPI Jar files
The [latest ESAPI release](https://github.com/ESAPI/esapi-java-legacy/releases/latest) is 2.2.1.0. The default configuration jar and its GPG signature can be found at [esapi-2.2.1.0-configuration.jar](https://github.com/ESAPI/esapi-java-legacy/releases/download/esapi-2.2.1.0/esapi-2.2.1.0-configuration.jar) and [esapi-2.2.1.0-configuration.jar.asc](https://github.com/ESAPI/esapi-java-legacy/releases/download/esapi-2.2.1.0/esapi-2.2.1.0-configuration.jar.asc) respectively.

The latest regular ESAPI jars can are available from Maven Central.

However, before you start a *new* project using ESAPI, but sure to read "[Should I use ESAPI?](https://owasp.org/www-project-enterprise-security-api/#div-shouldiuseesapi)".

# ESAPI Deprecation Policy
Unless we unintentionally screw-up, our intent is to keep classes, methods, and/or fields whihc have been annotated as "@deprecated" for a minimum of two (2) years or until the next major release number (e.g., 3.x as of now), which ever comes first, before we remove them.
Note that this policy does not apply to classes under the **org.owasp.esapi.reference** package. You are not expected to be using such classes directly in your code.

# Contributing to ESAPI legacy
## How can I contribute or help with fix bugs?
Fork and submit a pull request! Simple as pi! We generally only accept bug fixes, not new features because as a legacy project, we don't intend on adding new features, although we may make exceptions. If you wish to propose a new feature, the best place to discuss it is via the ESAPI-DEV mailing list mentioned below. Note that we vet all pull requests, including coding style of any contributions; use the same coding style found in the files you are already editing.

If you are new to ESAPI, a good place to start is to look for GitHub issues labled as 'good first issue'. (E.g., to find all open issues with that label, use https://github.com/ESAPI/esapi-java-legacy/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22.)

You can find additional details in the file '[CONTRIBUTING-TO-ESAPI.txt](https://raw.githubusercontent.com/ESAPI/esapi-java-legacy/develop/CONTRIBUTING-TO-ESAPI.txt)'.

### What happened to Google code?
In mid-2014 ESAPI Migrated all code to GitHub. This migration was completed in November 2014.

### What about the issues still located on Google Code?
All issues from Google Code have been migrated to GitHub issues. We have a JIRA/Confluence instance allocated to us, but it has not be configured to synchronize with the GitHub issues, and thus is should not be used. JIRA is fine, but if we can't have it synchronized with GitHub issues (which is where the majority of our users report issues), it is not usuable. As developers, we do not want to spent time having to close issues from multiple bug-tracking sites. Therefore, until this synchronization happens (see GitHub issue #371), please ONLY use GitHub for reporting bugs.

When reporting an issue, please be clear and try to ensure that the ESAPI development team has sufficient information to be able to reproduce your results. If you have not already done so, this might be a good time to read Eric S. Raymond's classic "How to Ask Questions the Smart Way", at http://www.catb.org/esr/faqs/smart-questions.html before posting your issue.

### Find an Issue?
If you have found a bug, then create an issue on the esapi-legacy-java repo: https://github.com/ESAPI/esapi-java-legacy/issues

NOTE: Please do NOT use GitHub issues to ask questions about ESAPI. If you wish to do this, post to either of the 2 mailing lists (now on Google Groups) found at the bottom of this page. If we find questions as GitHub issues, we simply will close them and direct you to do this anyhow.

### Find a Vulnerability?
If you have found a vulnerability in ESAPI legacy, first search the issues list (see above) to see if it has already been reported. If it has not, then please contact both Kevin W. Wall (kevin.w.wall at gmail.com) and Matt Seil (matt.seil at owasp.org) directly. Please do not report vulnerabilities via GitHub issues or via the ESAPI mailing lists as we wish to keep our users secure while a patch is implemented and deployed. If you wish to be acknowledged for finding the vulnerability, then please follow this process. (Eventually, we would like to have BugCrowd handle this, but that's still a ways off.) Also, when you post the email describing the vulnerability, please do so from an email address that you usually monitor.

More detail is available in the file '[SECURITY.md](https://raw.githubusercontent.com/ESAPI/esapi-java-legacy/develop/SECURITY.md)'.

## Where to Find More Information on ESAPI

*Wiki:* https://owasp.org/www-project-enterprise-security-api/

*Nightly Build:* Travis CI - https://travis-ci.org/bkimminich/esapi-java-legacy

~~JIRA: https://owasp-esapi.atlassian.net/browse/ESAPILEG~~<br />Issues: Until further notice, use the GitHub issues for reporting bugs and enhancement requests.


*Documentation:* https://owasp-esapi.atlassian.net/wiki/display/ESAPILEG/ESAPI+Legacy (Coming Soon), for now find general documentation under the 'documentation/' directory, and the latest Javadoc under https://www.javadoc.io/doc/org.owasp.esapi/esapi/

*Realtime Support available on our IRC Channel:*<br/>
Server: irc.freenode.net<br/>
Channel: #esapi<br/>
Webchat http://webchat.freenode.net/

*Mailing lists:*
As of 2019-03-25, ESAPI's 2 mailing lists were officially moved OFF of their Mailman mailing lists to a new home on Google Groups.

The names of the 2 Google Groups are "[esapi-project-users](mailto:esapi-project-users@owasp.org)" and "[esapi-project-dev](mailto:esapi-project-dev@owasp.org)", which you may POST to *after* you subscribe to them via "[Subscribe to ESAPI Users list](https://groups.google.com/a/owasp.org/forum/#!forum/esapi-project-users/join)" and "[Subscribe to ESAPI Developers list](https://groups.google.com/a/owasp.org/forum/#!forum/esapi-project-dev/join)" respectively.

Old archives for the old Mailman mailing lists for ESAPI-Users and ESAPI-Dev are still available at https://lists.owasp.org/pipermail/esapi-users/ and https://lists.owasp.org/pipermail/esapi-dev/ respectively.

For a general overview of Google Groups and its web interface, see https://groups.google.com/forum/#!overview

For assistance subscribing and unsubscribing to Google Groups, see https://webapps.stackexchange.com/questions/13508/how-can-i-subscribe-to-a-google-mailing-list-with-a-non-google-e-mail-address/15593#15593

----------
OWASP is a registered trademark of the OWASP Foundation, Inc.
