# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.2.0.0  | :white_check_mark: |
| 2.1.0.1  | :x:, upgrade to 2.2.0.0|
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

## Security Bulletins

There are some ESAPI security bulletins published in the "documentation" directory on GitHub.
For details see:

* [Security Bulletin #1 - MAC Bypass in ESAPI Symmetric Encryption](documentation/ESAPI-security-bulletin1.pdf), which covers CVE-2013-5679 and CVE-2013-5960
* [Security Bulletin #2 - How Does CVE-2019-17571 Impact ESAPI?](documentation/ESAPI-security-bulletin2.pdf), which covers the Log4J 1 deserialization CVE.
* [Security Bulletin #3 - How Does the Apache Xerces Vulnerability(SNYK-JAVA-XERCES-608891) Impact ESAPI?](documentation/ESAPI-security-bulletin3.pdf), which decribes a unpatched Apache Xerces vulnerability similar to [CVE-2020-14621](https://nvd.nist.gov/vuln/detail/CVE-2020-14621)
