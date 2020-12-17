/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007-2019 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2007
 */
package org.owasp.esapi;

import java.io.IOException;
import java.net.URI;

import org.owasp.esapi.codecs.Codec;
import org.owasp.esapi.errors.EncodingException;


/**
 * The {@code Encoder} interface contains a number of methods for decoding input and encoding output
 * so that it will be safe for a variety of interpreters. Its primary use is to
 * provide <i>output</i> encoding to prevent XSS.
 * <p>
 * To prevent double-encoding, callers should make sure input does not already contain encoded characters
 * by calling one of the {@code canonicalize()} methods. Validator implementations should call
 * {@code canonicalize()} on user input <b>before</b> validating to prevent encoded attacks.
 * </p><p>
 * All of the methods <b>must</b> use an "allow list" or "positive" security model rather
 * than a "deny list" or "negative" security model.  For the encoding methods, this means that
 * all characters should be encoded, except for a specific list of "immune" characters that are
 * known to be safe.
 * </p><p>
 * The {@code Encoder} performs two key functions, encoding (also referred to as "escaping" in this Javadoc)
 * and decoding. These functions rely on a set of codecs that can be found in the
 * {@code org.owasp.esapi.codecs} package. These include:
 * <ul>
 * <li>CSS Escaping</li>
 * <li>HTMLEntity Encoding</li>
 * <li>JavaScript Escaping</li>
 * <li>MySQL Database Escaping</li>
 * <li>Oracle Database Escaping</li>
 * <li>Percent Encoding (aka URL Encoding)</li>
 * <li>Unix Shell Escaping</li>
 * <li>VBScript Escaping</li>
 * <li>Windows Cmd Escaping</li>
 * <li>LDAP Escaping</li>
 * <li>XML and XML Attribute Encoding</li>
 * <li>XPath Escaping</li>
 * <li>Base64 Encoding</li>
 * </ul>
 * </p><p>
 * The primary use of ESAPI {@code Encoder} is to prevent XSS vulnerabilities by
 * providing output encoding using the various "encodeFor<i>XYZ</i>()" methods,
 * where <i>XYZ</i> is one of CSS, HTML, HTMLAttribute, JavaScript, or URL. When
 * using the ESAPI output encoders, it is important that you use the one for the
 * <b>appropriate context</b> where the output will be rendered. For example, it
 * the output appears in an JavaScript context, you should use {@code encodeForJavaScript}
 * (note this includes all of the DOM JavaScript event handler attributes such as
 * 'onfocus', 'onclick', 'onload', etc.). If the output would be rendered in an HTML
 * attribute context (with the exception of the aforementioned 'onevent' type event
 * handler attributes), you would use {@code encodeForHTMLAttribute}. If you are
 * encoding anywhere a URL is expected (e.g., a 'href' attribute for for &lt;a&gt; or
 * a 'src' attribute on a &lt;img&gt; tag, etc.), then you should use use {@code encodeForURL}.
 * If encoding CSS, then use {@code encodeForCSS}. Etc. This is because there are
 * different escaping requirements for these different contexts. Developers who are
 * new to ESAPI or to defending against XSS vulnerabilities are highly encouraged to
 * <i>first</i> read the
 * <a href="https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html" target="_blank" rel="noopener noreferreer">
 * OWASP Cross-Site Scripting Prevention Cheat Sheet</a>.
 * </p><p>
 * Note that in addition to these encoder methods, ESAPI also provides a JSP Tag
 * Library ({@code META-INF/esapi.tld}) in the ESAPI jar. This allows one to use
 * the more convenient JSP tags in JSPs. These JSP tags are simply wrappers for the
 * various these "encodeForX<i>XYZ</i>()" method docmented in this {@code Encoder}
 * interface.
 * </p><p>
 * <b>Some important final words:</b>
 * <ul>
 * <li><b>Where to output encode for HTML rendering:</b>
 * Knowing <i>where</i> to place the output encoding in your code
 * is just as important as knowing which context (HTML, HTML attribute, CSS,
 * JavaScript, or URL) to use for the output encoding and surprisingly the two
 * are often related. In general, output encoding should be done just prior to the
 * output being rendered (that is, as close to the 'sink' as possible) because that
 * is what determines what the appropriate context is for the output encoding.
 * In fact, doing output encoding on untrusted data that is stored and to
 * be used later--whether stored in an HTTP session or in a database--is almost
 * always considered an anti-pattern. An example of this is one gathers and
 * stores some untrusted data item such as an email address from a user. A
 * developer thinks "let's output encode this and store the encoded data in
 * the database, thus making the untrusted data safe to use all the time, thus
* saving all of us developers all the encoding troubles later on". On the surface,
 * that sounds like a reasonable approach. The problem is how to know what
 * output encoding to use, not only for now, but for all possible <i>future</i>
 * uses? It might be that the current application code base is only using it in
 * an HTML context that is displayed in an HTML report or shown in an HTML
 * context in the user's profile. But what if it is later used in a {@code mailto:} URL?
 * Then instead of HTML encoding, it would need to have URL encoding. Similarly,
 * what if there is a later switch made to use AJAX and the untrusted email
 * address gets used in a JavaScript context? The complication is that even if
 * you know with certainty today all the ways that an untrusted data item is
 * used in your application, it is generally impossible to predict all the
 * contexts that it may be used in the future, not only in your application, but
 * in other applications that could access that data in the database.
 * </li>
 * <li><b>Avoiding multiple <i>nested</i> contexts:</b>
 * A really tricky situation to get correct is when there are multiple nested
 * encoding contexts. But far, the most common place this seems to come up is
 * untrusted URLs used in JavaScript. How should you handle that? Well,
 * the best way is to rewrite your code to avoid it!  An example of
 * this that is well worth reading may be found at
 * <a href="https://lists.owasp.org/pipermail/esapi-dev/2012-March/002090"
 * target="_blank" rel="noopener noreferrer">ESAPI-DEV mailing list archives:
 * URL encoding within JavaScript</a>. Be sure to read the entire thread.
 * The question itself is too nuanced to be answered in Javadoc, but now,
 * hopefully you are at least aware of the potential pitfalls. There is little
 * available research or examples on how to do output encoding when multiple
 * mixed encodings are required, although one that you may find useful is
 * <a href="https://arxiv.org/pdf/1804.01862.pdf" target="_blank"
 * rel="noopener noreferrer">
 * Automated Detecting and Repair of Cross-SiteScripting Vulnerabilities through Unit Testing</a>
 * It at least discusses a few of the common errors involved in multiple mixed
 * encoding contexts.
 * </li><li><b>A word about unit testing:</b>
 * Unit testing this is hard. You may be satisfied with stopped after you have
 * tested against the ubiquitous XSS test case of
 * <pre>
 *      &lt;/script&gt;alert(1)&lt;/script&gt;
 * </pre>
 * or similar simplistic XSS attack payloads and if that is properly encoded
 * (or, you don't see an alert box popped in your browser), you consider it
 * "problem fixed", and consider the unit testing sufficient. Unfortunately, that
 * minimalist testing may not always detect places where you used the wrong output
 * encoder. You need to do better. Fortunately, the aforementioned link,
 * <a href="https://arxiv.org/pdf/1804.01862.pdf" target="_blank"
 * rel="noopener noreferrer">
 * Automated Detecting and Repair of Cross-SiteScripting Vulnerabilities through Unit Testing</a>
 * provides some insight on this. You may also wish to look at the
 * <a href="https://github.com/ESAPI/esapi-java-legacy/blob/develop/src/test/java/org/owasp/esapi/reference/EncoderTest.java"
 * target="_blank" rel="noopener noreferrer">ESAPI Encoder JUnittest cases</a> for ideas.
 * If you are really ambitious, an excellent resource for XSS attack patterns is
 * <a href="https://beefproject.com/" target="_blank" rel="noopener noreferrer">BeEF - The Browser Exploitation Framework Project</a>.
 * </li>
 * </ul>
 * 
 * @see <a href="https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html">OWASP Cross-Site Scripting Prevention Cheat Sheet</a>
 * @see <a href="https://owasp.org/www-project-proactive-controls/v3/en/c4-encode-escape-data">OWASP Proactive Controls: C4: Encode and Escape Data</a>
 * @see <a href="https://www.onwebsecurity.com/security/properly-encoding-and-escaping-for-the-web.html" target="_blank" rel="noopener noreferrer">Properly encoding and escaping for the web</a>
 * @author Jeff Williams (jeff.williams .at. owasp.org)
 * @since June 1, 2007
 */
public interface Encoder {
    
    /**
     * This method is equivalent to calling {@code Encoder.canonicalize(input, restrictMultiple, restrictMixed);}.
     *
     * The default values for restrictMultiple and restrictMixed come from {@code ESAPI.properties}
     * <pre>
     * Encoder.AllowMultipleEncoding=false
     * Encoder.AllowMixedEncoding=false
     * </pre>
     *
     * @see #canonicalize(String, boolean, boolean)
     * @see <a href="http://www.w3.org/TR/html4/interact/forms.html#h-17.13.4">W3C specifications</a>
     * 
     * @param input the text to canonicalize
     * @return a String containing the canonicalized text
     */
    String canonicalize(String input);
    
    /**
     * This method is the equivalent to calling {@code Encoder.canonicalize(input, strict, strict);}.
     *
     * @see #canonicalize(String, boolean, boolean)
     * @see <a href="http://www.w3.org/TR/html4/interact/forms.html#h-17.13.4">W3C specifications</a>
     *  
     * @param input 
     *      the text to canonicalize
     * @param strict 
     *      true if checking for multiple and mixed encoding is desired, false otherwise
     * 
     * @return a String containing the canonicalized text
     */
    String canonicalize(String input, boolean strict);

    /**
     * Canonicalization is simply the operation of reducing a possibly encoded
     * string down to its simplest form. This is important, because attackers
     * frequently use encoding to change their input in a way that will bypass
     * validation filters, but still be interpreted properly by the target of
     * the attack. Note that data encoded more than once is not something that a
     * normal user would generate and should be regarded as an attack.
     * <p>
     * Everyone <a href="http://cwe.mitre.org/data/definitions/180.html">says</a> you shouldn't do validation
     * without canonicalizing the data first. This is easier said than done. The canonicalize method can
     * be used to simplify just about any input down to its most basic form. Note that canonicalize doesn't
     * handle Unicode issues, it focuses on higher level encoding and escaping schemes. In addition to simple
     * decoding, canonicalize also handles:
     * <ul><li>Perverse but legal variants of escaping schemes</li>
     * <li>Multiple escaping (%2526 or &#x26;lt;)</li>
     * <li>Mixed escaping (%26lt;)</li>
     * <li>Nested escaping (%%316 or &%6ct;)</li>
     * <li>All combinations of multiple, mixed, and nested encoding/escaping (%2&#x35;3c or &#x2526gt;)</li></ul>
     * <p>
     * Using canonicalize is simple. The default is just...
     * <pre>
     *     String clean = ESAPI.encoder().canonicalize( request.getParameter("input"));
     * </pre>
     * You need to decode untrusted data so that it's safe for ANY downstream interpreter or decoder. For
     * example, if your data goes into a Windows command shell, then into a database, and then to a browser,
     * you're going to need to decode for all of those systems. You can build a custom encoder to canonicalize
     * for your application like this...
     * <pre>
     *     ArrayList list = new ArrayList();
     *     list.add( new WindowsCodec() );
     *     list.add( new MySQLCodec() );
     *     list.add( new PercentCodec() );
     *     Encoder encoder = new DefaultEncoder( list );
     *     String clean = encoder.canonicalize( request.getParameter( "input" ));
     * </pre>
     * In ESAPI, the Validator uses the canonicalize method before it does validation.  So all you need to
     * do is to validate as normal and you'll be protected against a host of encoded attacks.
     * <pre>
     *     String input = request.getParameter( "name" );
     *     String name = ESAPI.validator().isValidInput( "test", input, "FirstName", 20, false);
     * </pre>
     * However, the default canonicalize() method only decodes HTMLEntity, percent (URL) encoding, and JavaScript
     * encoding. If you'd like to use a custom canonicalizer with your validator, that's pretty easy too.
     * <pre>
     *     ... setup custom encoder as above
     *     Validator validator = new DefaultValidator( encoder );
     *     String input = request.getParameter( "name" );
     *     String name = validator.isValidInput( "test", input, "name", 20, false);
     * </pre>
     * Although ESAPI is able to canonicalize multiple, mixed, or nested encoding, it's safer to not accept
     * this stuff in the first place. In ESAPI, the default is "strict" mode that throws an IntrusionException
     * if it receives anything not single-encoded with a single scheme. This is configurable
     * in {@code ESAPI.properties} using the properties:
     * <pre>
     * Encoder.AllowMultipleEncoding=false
     * Encoder.AllowMixedEncoding=false
     * </pre>
     * This method allows you to override the default behavior by directly specifying whether to restrict
     * multiple or mixed encoding. Even if you disable restrictions, you'll still get
     * warning messages in the log about each multiple encoding and mixed encoding received.
     * <pre>
     *     // disabling strict mode to allow mixed encoding
     *     String url = ESAPI.encoder().canonicalize( request.getParameter("url"), false, false);
     * </pre>
     * <b>WARNING!!!</b> Please note that this method is incompatible with URLs and if there exist any HTML Entities
     * that correspond with parameter values in a URL such as "&amp;para;" in a URL like 
     * "https://foo.com/?bar=foo&amp;parameter=wrong" you will get a mixed encoding validation exception.
     * <p>
     * If you wish to canonicalize a URL/URI use the method {@code Encoder.getCanonicalizedURI(URI dirtyUri);}
     *
     * @see <a href="http://www.w3.org/TR/html4/interact/forms.html#h-17.13.4">W3C specifications</a>
     * @see #getCanonicalizedURI(URI dirtyUri)
     *
     * @param input
     *      the text to canonicalize
     * @param restrictMultiple
     *      true if checking for multiple encoding is desired, false otherwise
     * @param restrictMixed
     *      true if checking for mixed encoding is desired, false otherwise
     *
     * @return a String containing the canonicalized text
     */
    String canonicalize(String input, boolean restrictMultiple, boolean restrictMixed);

    /**
     * Encode data for use in Cascading Style Sheets (CSS) content.
     * 
     * @see <a href="http://www.w3.org/TR/CSS21/syndata.html#escaped-characters">CSS Syntax [w3.org]</a>
     * 
     * @param untrustedData 
     *      the untrusted data to output encode for CSS
     * 
     * @return the untrusted data safely output encoded for use in a CSS
     */
    String encodeForCSS(String untrustedData);

    /**
     * Encode data for use in HTML using HTML entity encoding
     * <p> 
     * Note that the following characters:
     * 00-08, 0B-0C, 0E-1F, and 7F-9F
     * <p>cannot be used in HTML. 
     * 
     * @see <a href="http://en.wikipedia.org/wiki/Character_encodings_in_HTML">HTML Encodings [wikipedia.org]</a> 
     * @see <a href="http://www.w3.org/TR/html4/sgml/sgmldecl.html">SGML Specification [w3.org]</a>
     * @see <a href="http://www.w3.org/TR/REC-xml/#charsets">XML Specification [w3.org]</a>
     * 
     * @param untrustedData 
     *      the untrusted data to output encode for HTML
     * 
     * @return the untrusted data safely output encoded for use in a HTML
     */
    String encodeForHTML(String untrustedData);

    /**
     * Decodes HTML entities.
     * @param input the <code>String</code> to decode
     * @return the newly decoded <code>String</code>
     */
    String decodeForHTML(String input);
        
    /**
     * Encode data for use in HTML attributes.
     * 
     * @param untrustedData 
     *      the untrusted data to output encode for an HTML attribute
     * 
     * @return the untrusted data safely output encoded for use in a use as an HTML attribute
     */
    String encodeForHTMLAttribute(String untrustedData);


    /**
     * Encode data for insertion inside a data value or function argument in JavaScript. Including user data 
     * directly inside a script is quite dangerous. Great care must be taken to prevent including user data
     * directly into script code itself, as no amount of encoding will prevent attacks there.
     * 
     * Please note there are some JavaScript functions that can never safely receive untrusted data 
     * as input – even if the user input is encoded.
     * 
     * For example:
     * <pre>
     *  &lt;script&gt;
     *    &nbsp;&nbsp;window.setInterval('&lt;%= EVEN IF YOU ENCODE UNTRUSTED DATA YOU ARE XSSED HERE %&gt;');
     *  &lt;/script&gt;
     * </pre>
     * @param untrustedData 
     *          the untrusted data to output encode for JavaScript
     * 
     * @return the untrusted data safely output encoded for use in a use in JavaScript
     */
    String encodeForJavaScript(String untrustedData);

    /**
     * Encode data for insertion inside a data value in a Visual Basic script. Putting user data directly
     * inside a script is quite dangerous. Great care must be taken to prevent putting user data
     * directly into script code itself, as no amount of encoding will prevent attacks there.
     * 
     * This method is not recommended as VBScript is only supported by Internet Explorer
     * 
     * @param untrustedData 
     *      the untrusted data to output encode for VBScript
     * 
     * @return the untrusted data safely output encoded for use in a use in VBScript
     */
    String encodeForVBScript(String untrustedData);


    /**
     * Encode input for use in a SQL query, according to the selected codec 
     * (appropriate codecs include the MySQLCodec and OracleCodec).
     * 
     * This method is not recommended. The use of the {@code PreparedStatement}
     * interface is the preferred approach. However, if for some reason 
     * this is impossible, then this method is provided as a weaker 
     * alternative. 
     * 
     * The best approach is to make sure any single-quotes are double-quoted.
     * Another possible approach is to use the {escape} syntax described in the
     * JDBC specification in section 1.5.6.
     *
     * However, this syntax does not work with all drivers, and requires
     * modification of all queries.
     * 
     * @see <a href="https://download.oracle.com/otn-pub/jcp/jdbc-4_2-mrel2-spec/jdbc4.2-fr-spec.pdf">JDBC Specification</a>
     * @see <a href="https://docs.oracle.com/javase/8/docs/api/java/sql/PreparedStatement.html">java.sql.PreparedStatement</a>
     *  
     * @param codec 
     *      a Codec that declares which database 'input' is being encoded for (ie. MySQL, Oracle, etc.)
     * @param input 
     *      the text to encode for SQL
     * 
     * @return input encoded for use in SQL
     */
    String encodeForSQL(Codec codec, String input);

    /**
     * Encode for an operating system command shell according to the selected codec (appropriate codecs include the WindowsCodec and UnixCodec). 
     *
     * Please note the following recommendations before choosing to use this method: 
     * 
     * 1)      It is strongly recommended that applications avoid making direct OS system calls if possible as such calls are not portable, and they are potentially unsafe. Please use language provided features if at all possible, rather than native OS calls to implement the desired feature.
     * 2)      If an OS call cannot be avoided, then it is recommended that the program to be invoked be invoked directly (e.g., System.exec("nameofcommand" + "parameterstocommand");) as this avoids the use of the command shell. The "parameterstocommand" should of course be validated before passing them to the OS command.
     * 3)      If you must use this method, then we recommend validating all user supplied input passed to the command shell as well, in addition to using this method in order to make the command shell invocation safe.
     *  
     * An example use of this method would be: System.exec("dir " + ESAPI.encodeForOS(WindowsCodec, "parameter(s)tocommandwithuserinput");
     * 
     * @param codec 
     *      a Codec that declares which operating system 'input' is being encoded for (ie. Windows, Unix, etc.)
     * @param input 
     *      the text to encode for the command shell
     * 
     * @return input encoded for use in command shell
     */
    String encodeForOS(Codec codec, String input);

    /**
     * Encode data for use in LDAP queries. Wildcard (*) characters will be encoded.
     * 
     * @param input 
     *      the text to encode for LDAP
     * 
     * @return input encoded for use in LDAP
     */
    String encodeForLDAP(String input);

    /**
     * Encode data for use in LDAP queries. You have the option whether or not to encode wildcard (*) characters.
     * 
     * @param input 
     *      the text to encode for LDAP
     * @param encodeWildcards 
     *      whether or not wildcard (*) characters will be encoded.
     *
     * @return input encoded for use in LDAP
     */
    String encodeForLDAP(String input, boolean encodeWildcards);
     
    /**
     * Encode data for use in an LDAP distinguished name.
     * 
     *  @param input 
     *          the text to encode for an LDAP distinguished name
     * 
     *  @return input encoded for use in an LDAP distinguished name
     */
    String encodeForDN(String input);

    /**
     * Encode data for use in an XPath query.
     * 
     * NB: The reference implementation encodes almost everything and may over-encode. 
     * 
     * The difficulty with XPath encoding is that XPath has no built in mechanism for escaping
     * characters. It is possible to use XQuery in a parameterized way to
     * prevent injection. 
     * 
     * For more information, refer to <a
     * href="http://www.ibm.com/developerworks/xml/library/x-xpathinjection.html">this
     * article</a> which specifies the following list of characters as the most
     * dangerous: ^&"*';<>(). <a
     * href="http://www.packetstormsecurity.org/papers/bypass/Blind_XPath_Injection_20040518.pdf">This
     * paper</a> suggests disallowing ' and " in queries.
     * 
     * @see <a href="http://www.ibm.com/developerworks/xml/library/x-xpathinjection.html">XPath Injection [ibm.com]</a>
     * @see <a href="http://www.packetstormsecurity.org/papers/bypass/Blind_XPath_Injection_20040518.pdf">Blind XPath Injection [packetstormsecurity.org]</a>
     *  
     * @param input
     *      the text to encode for XPath
     * @return 
     *      input encoded for use in XPath
     */
    String encodeForXPath(String input);

    /**
     * Encode data for use in an XML element. The implementation should follow the <a
     * href="https://www.w3.org/TR/REC-xml/#charencoding">Character Encoding in Entities</a>
     * from W3C.
     * <p>
     * The use of a real XML parser is strongly encouraged. However, in the
     * hopefully rare case that you need to make sure that data is safe for
     * inclusion in an XML document and cannot use a parser, this method provides
     * a safe mechanism to do so.
     * 
     * @see <a href="https://www.w3.org/TR/REC-xml/#charencoding">Character Encoding in Entities</a>
     * 
     * @param input
     *          the text to encode for XML
     * 
     * @return
     *          input encoded for use in XML
     */
    String encodeForXML(String input);

    /**
     * Encode data for use in an XML attribute. The implementation should follow the <a
     * href="https://www.w3.org/TR/REC-xml/#charencoding">Character Encoding in Entities</a>
     * from W3C.
     * <p>
     * The use of a real XML parser is highly encouraged. However, in the
     * hopefully rare case that you need to make sure that data is safe for
     * inclusion in an XML document and cannot use a parse, this method provides
     * a safe mechanism to do so.
     * 
     * @see <a href="https://www.w3.org/TR/REC-xml/#charencoding">Character Encoding in Entities</a>
     * 
     * @param input
     *          the text to encode for use as an XML attribute
     * 
     * @return 
     *          input encoded for use in an XML attribute
     */
    String encodeForXMLAttribute(String input);

    /**
     * Encode for use in a URL. This method performs <a
     * href="http://en.wikipedia.org/wiki/Percent-encoding">URL encoding</a>
     * on the entire string.
     * 
     * @see <a href="http://en.wikipedia.org/wiki/Percent-encoding">URL encoding</a>
     * 
     * @param input 
     *      the text to encode for use in a URL
     * 
     * @return input 
     *      encoded for use in a URL
     * 
     * @throws EncodingException 
     *      if encoding fails
     */
    String encodeForURL(String input) throws EncodingException;

    /**
     * Decode from URL. Implementations should first canonicalize and
     * detect any double-encoding. If this check passes, then the data is decoded using URL
     * decoding.
     * 
     * @param input 
     *      the text to decode from an encoded URL
     * 
     * @return 
     *      the decoded URL value
     * 
     * @throws EncodingException 
     *      if decoding fails
     */
    String decodeFromURL(String input) throws EncodingException;

    /**
     * Encode for Base64.
     * 
     * @param input 
     *      the text to encode for Base64
     * @param wrap
     *      the encoder will wrap lines every 64 characters of output
     * 
     * @return input encoded for Base64
     */
    String encodeForBase64(byte[] input, boolean wrap);

    /**
     * Decode data encoded with BASE-64 encoding.
     * 
     * @param input 
     *      the Base64 text to decode
     * 
     * @return input decoded from Base64
     * 
     * @throws IOException
     */
    byte[] decodeFromBase64(String input) throws IOException;

    /**
     * Get a version of the input URI that will be safe to run regex and other validations against.  
     * It is not recommended to persist this value as it will transform user input.  This method 
     * will not test to see if the URI is RFC-3986 compliant.
     * 
     * @param dirtyUri
     *      the tainted URI
     * @return The canonicalized URI
     */
    String getCanonicalizedURI(URI dirtyUri);

}
