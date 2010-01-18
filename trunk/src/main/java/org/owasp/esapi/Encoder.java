/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2007
 */
package org.owasp.esapi;

import java.io.IOException;

import org.owasp.esapi.codecs.Codec;
import org.owasp.esapi.errors.EncodingException;


/**
 * The Encoder interface contains a number of methods for decoding input and encoding output
 * so that it will be safe for a variety of interpreters. To prevent
 * double-encoding, callers should make sure input does not already contain encoded characters
 * by calling canonicalize. Validator implementations should call canonicalize on user input
 * <b>before</b> validating to prevent encoded attacks.
 * <P>
 * <img src="doc-files/Encoder.jpg">
 * <P>
 * All of the methods must use a "whitelist" or "positive" security model.
 * For the encoding methods, this means that all characters should be encoded, except for a specific list of
 * "immune" characters that are known to be safe.
 * <p>
 * The Encoder performs two key functions, encoding and decoding. These functions rely
 * on a set of codecs that can be found in the org.owasp.esapi.codecs package. These include:
 * <ul><li>CSS Escaping</li>
 * <li>HTMLEntity Encoding</li>
 * <li>JavaScript Escaping</li>
 * <li>MySQL Escaping</li>
 * <li>Oracle Escaping</li>
 * <li>Percent Encoding (aka URL Encoding)</li>
 * <li>Unix Escaping</li>
 * <li>VBScript Escaping</li>
 * <li>Windows Encoding</li></ul>
 * <p>
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 */
public interface Encoder {
	
	/**
	 * Standard character sets
	 */

	/**  
	 * @deprecated Use {@link EncoderConstants#CHAR_LOWERS} instead*/
	@Deprecated
	public final static char[] CHAR_LOWERS = EncoderConstants.CHAR_LOWERS;
    /**
	 * @deprecated Use {@link EncoderConstants#CHAR_UPPERS} instead
	 *
	 */
	@Deprecated
	public final static char[] CHAR_UPPERS = EncoderConstants.CHAR_UPPERS;
    /**
	 * @deprecated Use {@link EncoderConstants#CHAR_DIGITS} instead
	 *
	 */
	@Deprecated
	public final static char[] CHAR_DIGITS = EncoderConstants.CHAR_DIGITS;
    /**
	 * @deprecated Use {@link EncoderConstants#CHAR_SPECIALS} instead
	 *
	 */
	@Deprecated
	public final static char[] CHAR_SPECIALS = EncoderConstants.CHAR_SPECIALS;
    /**
	 * @deprecated Use {@link EncoderConstants#CHAR_LETTERS} instead
	 *
	 */
	@Deprecated
	public final static char[] CHAR_LETTERS = EncoderConstants.CHAR_LETTERS;
    /**
	 * @deprecated Use {@link EncoderConstants#CHAR_ALPHANUMERICS} instead
	 *
	 */
	@Deprecated
	public final static char[] CHAR_ALPHANUMERICS = EncoderConstants.CHAR_ALPHANUMERICS;
	
	
	/**
	 * Password character set, is alphanumerics (without l, i, I, o, O, and 0)
	 * selected specials like + (bad for URL encoding, | is like i and 1,
	 * etc...)
	 * @deprecated Use {@link EncoderConstants#CHAR_PASSWORD_LOWERS} instead
	 */
	@Deprecated
	public final static char[] CHAR_PASSWORD_LOWERS = EncoderConstants.CHAR_PASSWORD_LOWERS;
    /**
	 * @deprecated Use {@link EncoderConstants#CHAR_PASSWORD_UPPERS} instead
	 *
	 */
	@Deprecated
	public final static char[] CHAR_PASSWORD_UPPERS = EncoderConstants.CHAR_PASSWORD_UPPERS;
    /**
	 * @deprecated Use {@link EncoderConstants#CHAR_PASSWORD_DIGITS} instead
	 *
	 */
	@Deprecated
	public final static char[] CHAR_PASSWORD_DIGITS = EncoderConstants.CHAR_PASSWORD_DIGITS;
    /**
	 * @deprecated Use {@link EncoderConstants#CHAR_PASSWORD_SPECIALS} instead
	 *
	 */
	@Deprecated
	public final static char[] CHAR_PASSWORD_SPECIALS = EncoderConstants.CHAR_PASSWORD_SPECIALS;
    /**
	 * @deprecated Use {@link EncoderConstants#CHAR_PASSWORD_LETTERS} instead
	 *
	 */
	@Deprecated
	public final static char[] CHAR_PASSWORD_LETTERS = EncoderConstants.CHAR_PASSWORD_LETTERS;
    


	/**
	 * This method is equivalent to calling <pre>Encoder.canonicalize(input, true);</pre>
	 * 
	 * @see <a href="http://www.w3.org/TR/html4/interact/forms.html#h-17.13.4">W3C specifications</a>
	 * 
	 * @param input the text to canonicalize
	 * @return a String containing the canonicalized text
	 */
	String canonicalize(String input);
	
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
     * if it receives anything not single-encoded with a single scheme.  Currently this is not configurable 
     * in ESAPI.properties, but it probably should be.  Even if you disable "strict" mode, you'll still get
     * warning messages in the log about each multiple encoding and mixed encoding received.
     * <pre>
     *     // disabling strict mode to allow mixed encoding
     *     String url = ESAPI.encoder().canonicalize( request.getParameter("url"), false);
     * </pre>
	 * 
	 * @see <a href="http://www.w3.org/TR/html4/interact/forms.html#h-17.13.4">W3C specifications</a>
	 *  
	 * @param input 
	 * 		the text to canonicalize
	 * @param strict 
	 * 		true if checking for double encoding is desired, false otherwise
	 * 
	 * @return a String containing the canonicalized text
	 */
	String canonicalize(String input, boolean strict);

	/**
	 * Encode data for use in Cascading Style Sheets (CSS) content.
	 * 
	 * @see <a href="http://www.w3.org/TR/CSS21/syndata.html#escaped-characters">CSS Syntax [w3.org]</a>
	 * 
	 * @param input 
	 * 		the text to encode for CSS
	 * 
	 * @return input encoded for CSS
	 */
	String encodeForCSS(String input);

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
	 * @param input 
	 * 		the text to encode for HTML
	 * 
	 * @return input encoded for HTML
	 */
	String encodeForHTML(String input);

	/**
     * Decodes HTML entities.
     * @param input the <code>String</code> to decode
     * @return the newly decoded <code>String</code>
     */
	String decodeForHTML(String input);
		
	/**
	 * Encode data for use in HTML attributes.
	 * 
	 * @param input 
	 * 		the text to encode for an HTML attribute
	 * 
	 * @return input encoded for use as an HTML attribute
	 */
	String encodeForHTMLAttribute(String input);

	/**
	 * Encode data for insertion inside a data value in JavaScript. Putting user data directly
	 * inside a script is quite dangerous. Great care must be taken to prevent putting user data
	 * directly into script code itself, as no amount of encoding will prevent attacks there.
	 * 
	 * @param input 
	 * 		the text to encode for JavaScript
	 * 
	 * @return input encoded for use in JavaScript
	 */
	String encodeForJavaScript(String input);

	/**
	 * Encode data for insertion inside a data value in a Visual Basic script. Putting user data directly
	 * inside a script is quite dangerous. Great care must be taken to prevent putting user data
	 * directly into script code itself, as no amount of encoding will prevent attacks there.
	 * 
	 * This method is not recommended as VBScript is only supported by Internet Explorer
	 * 
	 * @param input 
	 * 		the text to encode for VBScript
	 * 
	 * @return input encoded for use in VBScript
	 */
	String encodeForVBScript(String input);


	/**
	 * Encode input for use in a SQL query, according to the selected codec 
	 * (appropriate codecs include the MySQLCodec and OracleCodec).
	 * 
	 * This method is not recommended. The use of the PreparedStatement 
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
	 * @see <a href="http://java.sun.com/j2se/1.4.2/docs/guide/jdbc/getstart/statement.html">JDBC Specification</a>
	 *  
	 * @param codec 
	 * 		a Codec that declares which database 'input' is being encoded for (ie. MySQL, Oracle, etc.)
	 * @param input 
	 * 		the text to encode for SQL
	 * 
	 * @return input encoded for use in SQL
	 */
	String encodeForSQL(Codec codec, String input);

	/**
	 * Encode for an operating system command shell according to the selected codec (appropriate codecs include
	 * the WindowsCodec and UnixCodec).
	 * 
	 * @param codec 
	 * 		a Codec that declares which operating system 'input' is being encoded for (ie. Windows, Unix, etc.)
	 * @param input 
	 * 		the text to encode for the command shell
	 * 
	 * @return input encoded for use in command shell
	 */
	String encodeForOS(Codec codec, String input);

	/**
	 * Encode data for use in LDAP queries.
	 * 
	 * @param input 
	 * 		the text to encode for LDAP
	 * 
	 * @return input encoded for use in LDAP
	 */
	String encodeForLDAP(String input);

	/**
	 * Encode data for use in an LDAP distinguished name.
	 * 
	 *  @param input 
	 *  		the text to encode for an LDAP distinguished name
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
	 * 		input encoded for use in XPath
	 */
	String encodeForXPath(String input);

	/**
	 * Encode data for use in an XML element. The implementation should follow the <a
	 * href="http://www.w3schools.com/xml/xml_encoding.asp">XML Encoding
	 * Standard</a> from the W3C.
	 * <p>
	 * The use of a real XML parser is strongly encouraged. However, in the
	 * hopefully rare case that you need to make sure that data is safe for
	 * inclusion in an XML document and cannot use a parse, this method provides
	 * a safe mechanism to do so.
	 * 
	 * @see <a href="http://www.w3schools.com/xml/xml_encoding.asp">XML Encoding Standard</a>
	 * 
	 * @param input
	 * 			the text to encode for XML
	 * 
	 * @return
	 *			input encoded for use in XML
	 */
	String encodeForXML(String input);

	/**
	 * Encode data for use in an XML attribute. The implementation should follow
	 * the <a href="http://www.w3schools.com/xml/xml_encoding.asp">XML Encoding
	 * Standard</a> from the W3C.
	 * <p>
	 * The use of a real XML parser is highly encouraged. However, in the
	 * hopefully rare case that you need to make sure that data is safe for
	 * inclusion in an XML document and cannot use a parse, this method provides
	 * a safe mechanism to do so.
	 * 
	 * @see <a href="http://www.w3schools.com/xml/xml_encoding.asp">XML Encoding Standard</a>
	 * 
	 * @param input
	 * 			the text to encode for use as an XML attribute
	 * 
	 * @return 
	 * 			input encoded for use in an XML attribute
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
	 * 		the text to encode for use in a URL
	 * 
	 * @return input 
	 * 		encoded for use in a URL
	 * 
	 * @throws EncodingException 
	 * 		if encoding fails
	 */
	String encodeForURL(String input) throws EncodingException;

	/**
	 * Decode from URL. Implementations should first canonicalize and
	 * detect any double-encoding. If this check passes, then the data is decoded using URL
	 * decoding.
	 * 
	 * @param input 
	 * 		the text to decode from an encoded URL
	 * 
	 * @return 
	 * 		the decoded URL value
	 * 
	 * @throws EncodingException 
	 * 		if decoding fails
	 */
	String decodeFromURL(String input) throws EncodingException;

	/**
	 * Encode for Base64.
	 * 
	 * @param input 
	 * 		the text to encode for Base64
	 * @param wrap
	 * 		the encoder will wrap lines every 64 characters of output
	 * 
	 * @return input encoded for Base64
	 */
	String encodeForBase64(byte[] input, boolean wrap);

	/**
	 * Decode data encoded with BASE-64 encoding.
	 * 
	 * @param input 
	 * 		the Base64 text to decode
	 * 
	 * @return input 
	 * 		decoded from Base64
	 * 
	 * @throws IOException
	 */
	byte[] decodeFromBase64(String input) throws IOException;

}
