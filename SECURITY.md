# Security Policy

In general, because the ESAPI core development is so small (3 people, all
working full time jobs), we can only support the latest version of ESAPI.
If you are locked in to some previous version and are unable to upgrade
to the latest version, perhaps one or more of us might consider back-porting
a patch (especially if it is the only way to address an ESAPI vulnerability),
but if it is anything but trivial, we would charge a TBD consulting fee.

## Supported Versions


| Version | Supported          |
| ------- | ------------------ |
| 2.7.0.0 (latest) | :white_check_mark: |
| 2.1.0.1-2.6.2.0 | :x:, upgrade to latest release |
| <= 1.4.x  | :x:, no longer supported AT ALL |

## Reporting a Vulnerability

If you believe that you have found a vulnerability in ESAPI, first please search the
GitHut issues list (for both open and closed issues) to see if it has already been reported.

If it has not, then please contact **both** of the project leaders, Kevin W. Wall
(kevin.w.wall at gmail.com) and Matt Seil (matt.seil at owasp.org) _directly_.
Please do **not** report any suspected vulnerabilities via GitHub issues
or via the ESAPI mailing lists as we wish to keep our users secure while a patch
is implemented and deployed. This is because if this is reported as a GitHub
issue or posted to either ESAPI mailing list, it more or less is equivalent to
dropping a 0-day on all applications using ESAPI. Instead, we encourage
responsible disclosure.

If you wish to be acknowledged for finding the vulnerability, then please follow
this process. One of the 2 ESAPI project leaders will try to contact you within
at least 5 business days, so when you post the email describing the
vulnerability, please do so from an email address that you usually monitor.
If you eventually wish to have it published as a CVE, we will also work with you
to ensure that you are given proper credit with MITRE and NIST. Even if you do
not wish to report the vulnerability as a CVE, we will acknowledge you when we
create a GitHub issue (once the issue is patched) as well as acknowledging you
in any security bulletin that we may write up and use to notify our users. (If you wish
to have your identity remain unknown, or perhaps you email address, we can work
with you on that as well.)

If possible, provide a working proof-of-concept or at least minimally describe
how it can be exploited in sufficient details that the ESAPI development team
can understand what needs to be done to fix it. Unfortunately at this time, we
are not in a position to pay out bug bounties for vulnerabilities.

Eventually, we would like to have BugCrowd handle this, but that's still a ways off.

## ESAPI Security Bulletins and GitHub Security Advisories

There are some ESAPI security bulletins published in the "documentation" directory on GitHub.
GitHub also has published some Security Advisories for ESAPI.
For details, see [Vulnerability Summary](https://github.com/ESAPI/esapi-java-legacy/blob/develop/Vulnerability-Summary.md).

