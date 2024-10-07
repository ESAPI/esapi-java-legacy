Enterprise Security API for Java (Legacy)
=================

[![Build Status](https://travis-ci.org/bkimminich/esapi-java-legacy.svg?branch=master)](https://travis-ci.org/bkimminich/esapi-java-legacy)
[![Coverage Status](https://coveralls.io/repos/github/bkimminich/esapi-java-legacy/badge.svg?branch=develop)](https://coveralls.io/github/bkimminich/esapi-java-legacy?branch=develop)
[![Coverity Status](https://scan.coverity.com/projects/8517/badge.svg)](https://scan.coverity.com/projects/bkimminich-esapi-java-legacy)
[![OpenSSF Best Practices](https://bestpractices.coreinfrastructure.org/projects/137/badge)](https://bestpractices.coreinfrastructure.org/projects/137)

<table border=10>
<tr>
<td>
OWASP® ESAPI (The OWASP Enterprise Security API) is a free, open source, web application security control library that makes it easier for programmers to write lower-risk applications. The ESAPI for Java library is designed to make it easier for programmers to retrofit security into existing applications. ESAPI for Java also serves as a solid foundation for new development.
</td>
</tr>
</table>

# Jakarta EE Support
**IMPORTANT:**
ESAPI has supported the Jakarta Servlet API (i.e., **jakarta.servlet.api**) since release
2.5.3.0.  (Unfortunately, this information was previously missing in this **README** file.)

Therefore, for release 2.5.3.0 and later versions of ESAPI, ESAPI ought to be able to support Spring Boot 3, Spring 6, Tomcat 10,
and other applications or libraries requiring Jarkata EE. (If you find a case where it does
not, please file a GitHub issue for it.)

The ESAPI jar file supporting Jakarta will be named esapi-_version_-jakarta.jar. To use that
specific Jakarta version of ESAPI, in Maven, you would specify your ESAPI dependency in your
**pom.xml** as:
```xml
<dependency>
    <groupId>org.owasp.esapi</groupId>
    <artifactId>esapi</artifactId>
    <version>2.5.5.0</version>  <!-- Preferably the latest version, but > 2.5.3.0 -->
    <classifier>jakarta</classifier>
</dependency>
```
(or any other version later than 2.5.3.0). Thanks to Jonathon Putney for creating a PR to
fix this. There is a long discussion in GitHub Discussion [#768](https://github.com/ESAPI/esapi-java-legacy/discussions/768)
where this was first announced, for those of you have insomnia or really long attention
spans and are interested in the approaches that were tried.

Of course, ESAPI also still continues to support the older Java EE Servlet API (i.e., **javax.servlet** namespace) as well. In
fact, without the
```xml
<classifier>jakarta</classifier>
```
that's the version that will be used by default.


# A word about ESAPI vulnerabilities
A summary of all the vulnerabilities that we have written about in either the
ESAPI Security Bulletins or in the GitHub Security Advisories may be found
in this [Vulnerability Summary](https://github.com/ESAPI/esapi-java-legacy/blob/develop/Vulnerability-Summary.md).
It is too lengthy, and if you are using the latest available ESAPI version--generally not relevant--to
place in this **README** file.

# Where are the OWASP ESAPI wiki pages?
You can find the official OWASP ESAPI Project wiki pages at
[https://owasp.org/www-project-enterprise-security-api/](https://owasp.org/www-project-enterprise-security-api/).
The ESAPI legacy GitHub repo also has several useful [wiki pages](https://github.com/ESAPI/esapi-java-legacy/wiki).

# What does Legacy mean?
This is the legacy branch of ESAPI which means it is an actively maintained branch of the project, however significant *new* **feature development** for this branch will *not* be done. Features that have already been scheduled for the 2.x branch will move forward.
Development for the "next generation" of ESAPI (starting with ESAPI 3.0), will be done at the
GitHub repository at [https://github.com/ESAPI/esapi-java](https://github.com/ESAPI/esapi-java).

**IMPORTANT NOTES:**
* The default branch for ESAPI legacy is the 'develop' branch (rather than the 'main' (formerly 'master') branch), where future development, bug fixes, etc. are now being done. The 'main' branch is now marked as "protected"; it reflects the latest stable ESAPI release (2.5.3.1 as of this date). Note that this change of making the 'develop' branch the default may affect any pull requests that you were intending to make.
* Also, the *minimal* baseline Java version to use ESAPI is now Java 8. (This was changed from Java 7 during the 2.4.0.0 release.)
* Support was dropped for Log4J 1 during ESAPI 2.5.0.0 release. If you need it, configure it via SLF4J. See  the
  [2.5.0.0 release notes](https://github.com/ESAPI/esapi-java-legacy/blob/develop/documentation/esapi4java-core-2.5.0.0-release-notes.txt)
for details.

# Where can I find ESAPI 3.x?
As mentioned above, you can find it at [https://github.com/ESAPI/esapi-java](https://github.com/ESAPI/esapi-java).

Note however that work on ESAPI 3 has not yet begun in earnest and is only
in its earliest planning stages. Even the code that is presently there
will likely change.

# ESAPI Release Notes
The ESAPI release notes may be found in ESAPI's "documentation" directory. They are generally named "esapi4java-core-*2.#.#.#*-release-notes.txt", where "*2.#.#.#*" refers to the ESAPI release number (which uses semantic versioning).

See the GitHub [Releases](https://github.com/ESAPI/esapi-java-legacy/releases) information for a list of releases which generally
link to the specific release notes.

### Really IMPORTANT information in release notes - Ignore at your peril
* Starting with ESAPI 2.2.1.0, important details changed reading the ESAPI
  Logger. If you have are getting things like ClassNotFoundException, you
  probably have not read it. Please be sure to read this specific section
  of the
  [2.2.1.0 release notes](https://github.com/ESAPI/esapi-java-legacy/blob/develop/documentation/esapi4java-core-2.2.1.0-release-notes.txt#L128-L155)
* Starting with ESAPI 2.2.3.0, ESAPI is using a version of AntiSamy that by default includes 'slf4j-simple' and
  does XML schema validation on the AntiSamy policy files. Please **READ** this
  section from the
  [2.2.3.0 release notes](https://github.com/ESAPI/esapi-java-legacy/blob/1312102e79d4ed98d1396f5c56e12f437534d62b/documentation/esapi4java-core-2.2.3.0-release-notes.txt#L22-L34)
  (at least the beginning portion) for some important notes that likely will affect your use of ESAPI! You have been warned!!!
* ESAPI 2.3.0.0 is the last release to support Java 7 as the minimal JDK.
  Starting with release 2.4.0.0, Java 8 or later is required.
* Starting with ESAPI 2.5.4.0, if you were using ESAPI's default logger, JUL
  (i.e., you had the property **ESAPI.Logger** set to "org.owasp.esapi.logging.java.JavaLogFactory"),
  then you must remove (or rename) the old ESAPI configuration file **esapi-java-logger.properties**.
  Failure to do so will cause ESAPI to throw a `ConfigurationException`, thereby
  preventing your application from starting. For important additional details, please see
  the ESAPI GitHub Discussion https://github.com/ESAPI/esapi-java-legacy/discussions/841.

# Locating ESAPI Jar files
The [latest ESAPI release](https://github.com/ESAPI/esapi-java-legacy/releases/latest) is 2.5.4.0.
All the *regular* ESAPI jars, with the exception of the ESAPI configuration
jar (i.e., esapi-2.#.#.#-configuration.jar) and its associated detached
GPG signature, are available from Maven Central. The ESAPI configuration
jars are linked under the 'Assets' section to each of the specific
ESAPI releases under the
GitHub [Releases page](https://github.com/ESAPI/esapi-java-legacy/releases).


However, **before** you start a *new* project using ESAPI, but sure to read "[Should I use ESAPI?](https://owasp.org/www-project-enterprise-security-api/#div-shouldiuseesapi)".

# ESAPI Deprecation Policy
Unless we unintentionally screw-up, our intent is to keep classes, methods,
and/or fields which have been annotated as "@deprecated" for a
minimum of two (2) years or until the next major release number (e.g.,
3.x as of now), which ever comes first, before we remove them. Note
that this policy does not apply to classes under
the **org.owasp.esapi.reference** package. You generally are not expected
to be using such classes directly in your code. At the ESAPI team's discretion,
it will also not apply for any known exploitable vulnerabilities for which
no available workaround exists.

## Exceptions to Deprecation Policy
We will make some exceptions to the normal 2 year period. In particular, in the
cases were we believe that keeping a specific deprecated class or method around
can introduce security issues (generally because many of you have a habit of
completely ignoring deprecation warnings), we sometimes will shorten that 2 year
period. When we decide to do that, we will announce that as part of the
deprecation message.

## Log4J 1.x Removal
**IMPORTANT NOTES:** As of ESAPI 2.5.0.0, all the Log4J 1.x related code
has been removed from the ESAPI code base (with the exception of some
references in documentation). If you must, you still should be able to
use Log4J 1.x logging via ESAPI SLF4J support. See the ESAPI 2.5.0.0 release
notes for further details.

# Quickstart - Maven Example
### Step 1: Add the required dependencies.
See https://mvnrepository.com/artifact/org.owasp.esapi/esapi/latest, the tab for
whatever build tool you are using. If you need the Jakarta version, make sure to
add
```xml
    <classifier>jakarta</classifier>
```
and include whatever jakara.servlet:jakarta.servlet-api version you are using with
```xml
    <scope>provided</scope>
```
### Step 2: Obtain the 2 properties files ESAPI.properties and validation.properties
1. Download these 2 files from the ESAPI release that you are using from https://github.com/ESAPI/esapi-java-legacy/releases
   and download the esapi-<release>-configuration.jar file (and the .asc file if you wish to confirm the GPG signature).
2. Unjar that configuration file that you just downloaded and find the 2
   properties files under the "configuration/esapi" subdirectory where you
   unjarred the config jar.
3. Read through Javadoc for [DefaultSecurityConfiguration](https://javadoc.io/static/org.owasp.esapi/esapi/2.5.4.0/org/owasp/esapi/reference/DefaultSecurityConfiguration.html)
   to understand the ways that ESAPI locates these files and then use the mechanism that works best for you. Copy the 2 properties
   files from the 'configuration/esapi' directory to the directory where you
   choose to have them reside. Note that you may also edit them to customize
   them according to your needs.

# Contributing to ESAPI legacy
### How can I contribute or help with fix bugs?
Fork and submit a pull request! Easy as pi! (How's that for an irrational
statement, you math nerds? :) We generally only accept bug fixes, not
new features because as a legacy project, we don't intend on adding new
features that we will have to maintain long term (although we may make
exceptions; see the 'New Features' section in this **README**). If
you are interesting in doing bug fixes though, the best place to start is the
[CONTRIBUTING-TO-ESAPI.txt](https://github.com/ESAPI/esapi-java-legacy/blob/develop/CONTRIBUTING-TO-ESAPI.txt)

If you are new to ESAPI, a good place to start is to look for GitHub issues labled as 'good first issue'. (E.g., to find all open issues with that label, use [https://github.com/ESAPI/esapi-java-legacy/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22](https://github.com/ESAPI/esapi-java-legacy/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22).)

Again, please find additional important details in the file
'[CONTRIBUTING-TO-ESAPI.txt](https://github.com/ESAPI/esapi-java-legacy/blob/develop/CONTRIBUTING-TO-ESAPI.txt)',
which will also describe the tool requirements.

#### Want to report an issue?
If you have found a bug, then create an issue on the esapi-legacy-java repo at [https://github.com/ESAPI/esapi-java-legacy/issues](https://github.com/ESAPI/esapi-java-legacy/issues)
As of May 11, 2022, we switched back to using (GitHub) issue templates. (We previously used issue templates when our source code repository was still on Google Code.) You can read more about our issue templates in this brief
[announcement](https://github.com/ESAPI/esapi-java-legacy/discussions/700).

NOTE: Please do **NOT** use GitHub issues to ask questions about ESAPI.
If you wish to ask questions, instead, post to either of the 2 mailing
lists (now on Google Groups) found the References section at the bottom
of this page. If we find questions posted as GitHub issues, we simply will
close them and direct you to do this anyhow. Alternately you may use the new
[Q&A](https://github.com/ESAPI/esapi-java-legacy/discussions/categories/q-a) section of our GitHub
[Discussions](https://github.com/ESAPI/esapi-java-legacy/discussions) page to ask questions.

When reporting an issue or just asking a question, please be clear and try
to ensure that the ESAPI development team has sufficient information to be
able to reproduce your results or to understand your question. If you have
not already done so, this might be a good time to read Eric S. Raymond's classic
"[How to Ask Questions the Smart Way](http://www.catb.org/esr/faqs/smart-questions.html)"
before posting your issue.

#### Find a Vulnerability?
If believe you have found a vulnerability in ESAPI legacy, for the sake of the
ESAPI community, please practice Responsible Disclosure. (Note: We will be sure
you get credit and will work with you to create a GitHub Security Advisory, and
if you so choose, to pursue filing a CVE via the GitHub CNA.)

You are of course encouraged to first search our GitHub issues list (see above)
to see if it has already been reported. If it has not, then please contact
both Kevin W. Wall (kevin.w.wall at gmail.com) and
Matt Seil (matt.seil at owasp.org) directly. Please do not report
vulnerabilities via GitHub issues or via the ESAPI mailing lists as
we wish to keep our users secure while a patch is implemented and
deployed. If you wish to be acknowledged for finding the vulnerability,
then please follow this process. Also, when you post the email describing
the vulnerability, please do so from an email address that you usually
monitor.

More detail is available in the file
'[SECURITY.md](https://github.com/ESAPI/esapi-java-legacy/blob/develop/SECURITY.md)'.
https://raw.githubusercontent.com/ESAPI/esapi-java-legacy/blob/develop/SECURITY.md)'.

### New Features
If you wish to propose a new feature, the best place to discuss it is via
new 'Discussions' board, probably under
'[Ideas](https://github.com/ESAPI/esapi-java-legacy/discussions/categories/ideas)',
or on the ESAPI-DEV mailing list mentioned below under the References section.
As mentioned previously, we generally are not considering new features
for ESAPI 2.x. This is because:
- ESAPI is already too monolithic and has too many dependencies for its size.
- We are trying to wind down support of ESAPI 2.x and get ESAPI 3.0 going so any
  resources we throw at ESAPI 2.x will slow down that goal.

That said, if you believe you have an idea for an additional simple feature that
does not pull in any additional 3rd party libraries, toss it out there for
discussion or even show us how it works with a PR. (Note that we vet all pull
requests, including coding style of any contributions, so please use the same
coding style found in the files you are already editing.)

# References: Where to Find More Information on ESAPI
**OWASP Wiki:** https://owasp.org/www-project-enterprise-security-api/

**GitHub ESAPI Wiki:** https://github.com/ESAPI/esapi-java-legacy/wiki

**General Documentation:** Under the '[documentation](https://github.com/ESAPI/esapi-java-legacy/tree/develop/documentation)' folder.

**OWASP Slack Channel:** [#owasp-esapi](https://owasp.slack.com/archives/CQ2ET27AN)

**GitHub Discussions:** [Discussions](https://github.com/ESAPI/esapi-java-legacy/discussions) - Not a lot there yet, but we only started this on May 11, 2022.

**Mailing lists:**
* As of 2019-03-25, ESAPI's 2 mailing lists were officially moved OFF of their Mailman mailing lists to a new home on Google Groups.
* The names of the 2 Google Groups are "[esapi-project-users](mailto:esapi-project-users@owasp.org)" and "[esapi-project-dev](mailto:esapi-project-dev@owasp.org)", which you may POST to *after* you subscribe to them via "[Subscribe to ESAPI Users list](https://groups.google.com/a/owasp.org/forum/#!forum/esapi-project-users/join)" and "[Subscribe to ESAPI Developers list](https://groups.google.com/a/owasp.org/forum/#!forum/esapi-project-dev/join)" respectively.
* Old archives for the old Mailman mailing lists for ESAPI-Users and ESAPI-Dev are still available at https://lists.owasp.org/pipermail/esapi-users/ and https://lists.owasp.org/pipermail/esapi-dev/ respectively.
* For a general overview of Google Groups and its web interface, see [https://groups.google.com/forum/#!overview](https://groups.google.com/forum/#!overview)
* For assistance subscribing and unsubscribing to Google Groups, see [https://webapps.stackexchange.com/questions/13508/how-can-i-subscribe-to-a-google-mailing-list-with-a-non-google-e-mail-address/15593#15593](https://webapps.stackexchange.com/questions/13508/how-can-i-subscribe-to-a-google-mailing-list-with-a-non-google-e-mail-address/15593#15593).

----------
OWASP is a registered trademark of the OWASP Foundation, Inc.
