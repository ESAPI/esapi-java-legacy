# Summary of ESAPI Security Bulletins and GitHub Security Advisories</h1>
This page attempts to summarize all the ESAPI Security Bulletins and GitHub Security Advisories in a table format. This started out as a lengthy email to the ESAPI User's Google group which you can find at
"<a href="https://groups.google.com/a/owasp.org/g/esapi-project-users/c/_CR8d-dpvMU">A word about Log4J vulnerabilities in ESAPI - the TL;DR version</a>"
but then morphed into this current format as more and more Log4J 1.x vulnerabilities were discovered as well as one in ESAPI itself that we felt compelled to detail.

<table cellspacing="0" border="2">
	<colgroup width="175"></colgroup>
	<colgroup width="265"></colgroup>
	<colgroup width="119"></colgroup>
	<colgroup width="199"></colgroup>
	<colgroup width="307"></colgroup>
	<colgroup width="450"></colgroup>
    <!-- Table heading row -->
	<tr>
		<td height="17" align="center"><b>Relevant ESAPI Security Bulletin / GitHub Security Advisory</b></td>
		<td align="center"><b>Summary</b></td>
		<td align="center"><b>Relevant CWEs</b></td>
		<td align="center"><b>Relevant Vuln ID</b></td>
		<td align="center"><b>Notes regarding potential impact</b></td>
		<td align="center"><b>ESAPI versions where default configuration is impacted</b></td>
	</tr>
	<tr>
		<td height="32" align="left"><a href="https://github.com/ESAPI/esapi-java-legacy/blob/develop/documentation/ESAPI-security-bulletin1.pdf">1</a></td>
		<td align="left">MAC bypass in ESAPI symmetric encryption</td>
		<td align="left"><a href="https://cwe.mitre.org/data/definitions/310.html">CWE-310</a></td>
		<td align="left"><a href="https://nvd.nist.gov/vuln/detail/CVE-2013-5679">CVE-2013-5679</a></td>
		<td align="left"><a class="comment-indicator"></a>
		MAC check may be bypassed thus not assuring the authenticity of the received ciphertext.</td>
		<td align="left">ESAPI 2.x versions before 2.1.0</td>
	</tr>
	<tr>
		<td height="62" align="left"><a href="https://github.com/ESAPI/esapi-java-legacy/blob/develop/documentation/ESAPI-security-bulletin2.pdf">2</a></td>
		<td align="left">Java deserialization vulnerability in Log4J 1 (via SocketServer) for ESAPI logging may lead to code injection</td>
		<td align="left"><a href="https://cwe.mitre.org/data/definitions/502.html">CWE-502</a></td>
        <td align="left"><a href="https://nvd.nist.gov/vuln/detail/CVE-2019-17571">CVE-2019-17571</a></td>
		<td align="left">SocketServer is a class presumably intended for aggregating Log4J log events. It is a server-side class. ESAPI does not use it, nor any Log4J 1 classes that use it.</td>
		<td align="left">None.<br>ESAPI 2.x versions 2.2.1.0 and later default to use JUL (java.util.logging)</td>
	</tr>
	<tr>
		<td height="77" align="left"><a href="https://github.com/ESAPI/esapi-java-legacy/blob/develop/documentation/ESAPI-security-bulletin3.pdf">3</a></td>
		<td align="left">This flaw allows a specially-crafted XML file to manipulate the validation process in processed by Xerces’ XMLSchemaValidation class in certain cases.</td>
		<td align="left"><a href="https://cwe.mitre.org/data/definitions/20.html">CWE-20</a></td>
		<td align="left"><a href="https://security.snyk.io/vuln/SNYK-JAVA-XERCES-608891">SNYK-JAVA-XERCES-608891</a> (related to <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-14621">CVE-2020-14621</a>)</td>
		<td align="left">An analysis of the ESAPI and Xerces code shows that ESAPI does not use the vulnerable Xerces class either directly or indirectly.</td>
		<td align="left">None, but fixed even with respect to SCA tools for ESAPI 2.2.3.0 and later which AntiSamy 1.6.2, which uses Xerces 2.12.1, where this vulnerability is fixed.</td>
	</tr>
	<tr>
		<td height="62" align="left"><a href="https://github.com/ESAPI/esapi-java-legacy/blob/develop/documentation/ESAPI-security-bulletin4.pdf">4</a></td>
		<td align="left">SMTPS (SMTP over SSL/TLS) can allow MITM attack if SMTPAppender is used with Log4J 1 ESAPI logging.</td>
		<td align="left"><a href="https://cwe.mitre.org/data/definitions/295.html">CWE-295</a></td>
        <td align="left"><a href="https://nvd.nist.gov/vuln/detail/CVE-2020-9488">CVE-2020-9488</a></td>
		<td align="left">If you are using Log4J 1’s SMTPAppender in your code, you already have a direct dependency that makes it exploitable. ESAPI does nothing to cause or prevent that.</td>
		<td align="left">None. ESAPI uses ConsoleAppender as the default appender even if ESAPI logging is configured to use Log4J 1.</td>
	</tr>
	<tr>
		<td height="122" align="left"><a href="https://github.com/ESAPI/esapi-java-legacy/blob/develop/documentation/ESAPI-security-bulletin5.pdf">5</a></td>
		<td align="left">Invoking the method Commons IO method, FileNameUtils.normalize() with an improper input string could allow a limited path traversal.</td>
		<td align="left"><a href="https://cwe.mitre.org/data/definitions/22.html">CWE-22</a></td>
        <td align="left"><a href="https://nvd.nist.gov/vuln/detail/CVE-2021-29425">CVE-2021-29425</a></td>
		<td align="left">Commons IO is being pulled in via AntiSamy, which pulls in Apache Batik-CSS.  Batik-CSS is part of a larger Apache Xmlgraphics Batik family.<br><br>Nothing in the Batik family of libraries uses org.apache.commons.io.FileNameUtils and neither ESAPI nor AntiSamy use Commons IO directly. Thus ESAPI is not affected by this CVE.</td>
		<td align="left">None. However may still show up in SCA output as AntiSamy using latest Apache Commons IO library version (2.6) that still support Java 7. AntiSamy 1.7 and later will require Java 8 as will ESAPI versions after 2.3.</td>
	</tr>
	<tr>
		<td height="115" align="left"><a href="https://github.com/ESAPI/esapi-java-legacy/blob/develop/documentation/ESAPI-security-bulletin6.pdf">6</a></td>
		<td align="left">Flaw in Log4J 1’s JSMAppender could cause insecure deserialization potentially leading to remote code execution.</td>
		<td align="left"><a href="https://cwe.mitre.org/data/definitions/502.html">CWE-502</a></td>
        <td align="left"><a href="https://nvd.nist.gov/vuln/detail/CVE-2021-4104">CVE-2021-4104</a></td>
		<td align="left">All versions of ESAPI are vulnerable and impacted if your application is doing all 3 of the following:<br>1) Using the deprecated ESAPI Log4J logging.<br>2) You have changed your default log4j.xml (or log4j.properties) file to use JMSAppender.<br>3) An attacker is able to overwrite the contents of your Log4J 1 configuration file.</td>
		<td align="left">None. ESAPI uses ConsoleAppender as the default appender even if ESAPI logging is configured to use Log4J 1.</td>
	</tr>
	<tr>
		<td height="115" align="left"><a href="https://github.com/ESAPI/esapi-java-legacy/blob/develop/documentation/ESAPI-security-bulletin7.pdf">7</a></td>
		<td align="left">Improper validation (or, specifically, not using parameterized SQL queries) of a SQL statement makes Apache Log4j JDBCAppender vulnerable to SQL Injection. This potentially could allow attackers to execute unintended SQL statements by entering data that is logged via Log4J 1.</td>
		<td align="left"><a href="https://cwe.mitre.org/data/definitions/89.html">CWE-89</a></td>
        <td align="left"><a href="https://nvd.nist.gov/vuln/detail/CVE-2022-23305">CVE-2022-23305</a></td>
		<td align="left">All versions of ESAPI are vulnerable and impacted if your application is doing both of the following:<br>1) Using the deprecated ESAPI Log4J logging.<br>2) You have changed your default log4j.xml (or log4j.properties) file to use JDBCAppender.</td>
		<td align="left">None. ESAPI uses ConsoleAppender as the default appender even if ESAPI logging is configured to use Log4J 1.</td>
	</tr>
	<tr>
		<td height="92" align="left"><a class="comment-indicator"></a>
		    <a href="https://github.com/ESAPI/esapi-java-legacy/blob/develop/documentation/ESAPI-security-bulletin8.pdf">8</a>
            <br/>
            <a href="https://github.com/ESAPI/esapi-java-legacy/security/advisories/GHSA-q77q-vx4q-xx6q">GHSA-q77q-vx4q-xx6q</a>
            </td>
		<td align="left">Improper sanitization of user-controlled input permitted by an incorrect regular expression in an ESAPI configuration file can result in that input being unintentionally executing javascript: URLs, resulting in Cross-Site Scripting (XSS).</td>
		<td align="left"><a href="https://cwe.mitre.org/data/definitions/79.html">CWE-79</a></td>
        <td align="left"><a href="https://nvd.nist.gov/vuln/detail/CVE-2022-24891">CVE-2022-24891</a></td>
		<td align="left">
            A malformed regular expression in ESAPI’s default AntiSamy policy file,
            “antisamy-esapi.xml”, accidentally allowed the “:” character to match as a part
            of the “onsiteURL” regular expression. This allowed
            'javascript:' pseudo-URIs to slip past ESAPI which could result in
            XSS vulnerabilities. Note that this vulnerability dates
            back at least to the ESAPI 1.4 release.
        </td>
		<td align="left">ESAPI 1.4 and all ESAPI 2.x versions before 2.3.0.0.</td>
	</tr>
	<tr>
		<td height="100" align="left">
            <a href="https://github.com/ESAPI/esapi-java-legacy/blob/develop/documentation/ESAPI-security-bulletin9.pdf">9</a>
        </td>
		<td align="left">
            Apache Log4j 1’s JMSSink is vulnerable to insecure deserialization of
            untrusted logged data when the attacker has write access to the
            Log4j configuration or if the configuration references an LDAP service
            that the attacker has access to. This may resulting in remote code
            execution.
        </td>
		<td align="left"><a href="https://cwe.mitre.org/data/definitions/502.html">CWE-502</a></td>
		<td align="left"><a href="https://nvd.nist.gov/vuln/detail/CVE-2022-23302">CVE-2022-23302</a></td>
		<td align="left">
             Remote Code Execution is possible.
        </td>
		<td align="left">
            None. ESAPI uses ConsoleAppender as the default appender even if ESAPI logging is configured to use Log4J 1.
        </td>
	</tr>

	<tr>
		<td height="115" align="left">
            <a href="https://github.com/ESAPI/esapi-java-legacy/blob/develop/documentation/ESAPI-security-bulletin10.pdf">10</a>
        </td>
		<td align="left">
            There is an RCE flaw caused by an insecure deserialization
            vulnerability in Apache Chainsaw, a Java-based GUI log viewer.
            CVE-2020-9493 identified a deserialization issue that was present in
            Apache Chainsaw 2.x prior to 2.1.0. However, prior to Chainsaw V2.0,
            Chainsaw was a component of Apache Log4j 1.2.x where the same
            issue exists and remains unfixed.
        </td>
		<td align="left">
            <a href="https://cwe.mitre.org/data/definitions/502.html">CWE-502</a>
        </td>
		<td align="left">
            <a href="https://nvd.nist.gov/vuln/detail/CVE-2022-23307">CVE-2022-23307</a>
        </td>
		<td align="left">
             Remote Code Execution is possible if you are running Apache Chainsaw 1.x from the Apache Log4J 1.2.x jar..
        </td>
		<td align="left">
            None. ESAPI uses ConsoleAppender as the default appender even if ESAPI logging is configured to use Log4J 1.
        </td>
	</tr>

	<tr>
		<td height="115" align="left">
            <a href="https://github.com/ESAPI/esapi-java-legacy/security/advisories/GHSA-8m5h-hrqm-pxm2">GHSA-8m5h-hrqm-pxm2</a>
        </td>
		<td align="left">
            The default implementation of Validator.getValidDirectoryPath(String, String, File, boolean)
            may incorrectly treat the tested input string as a child of the specified parent directory. This
            potentially could allow control-flow bypass checks to be defeated if an attack can specify
            the entire string representing the 'input' path.
        </td>
		<td align="left">
            <a href="https://cwe.mitre.org/data/definitions/22.html">CWE-22</a>
        </td>
		<td align="left">
            <a href="https://nvd.nist.gov/vuln/detail/CVE-2022-23457">CVE-2022-23457</a>
        </td>
		<td align="left">
             Control-flow bypass may be possible.
        </td>
		<td align="left">
            ESAPI 2.x, prior to the ESAPI 2.3.0.0 release. Version 2.3.0.0 and later are patched.
        </td>
	</tr>

</table>
