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
 * The Encoder interface contains a number of methods related to encoding input
 * so that it will be safe for a variety of interpreters. To prevent
 * double-encoding, all encoding methods should first check to see that the
 * input does not already contain encoded characters. There are a few methods
 * related to decoding that are used for canonicalization purposes. See the
 * Validator class for more information.
 * <P>
 * <img src="doc-files/Validator.jpg" height="600">
 * <P>
 * All of the methods here must use a "whitelist" or "positive" security model,
 * meaning that all characters should be encoded, except for a specific list of
 * "immune" characters that are known to be safe.
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 */
public interface Encoder {

	/** Standard character sets */
	public final static char[] CHAR_LOWERS = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
	public final static char[] CHAR_UPPERS = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' };
	public final static char[] CHAR_DIGITS = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' };
	public final static char[] CHAR_SPECIALS = { '.', '-', '_', '!', '@', '$', '^', '*', '=', '~', '|', '+', '?' };
	public final static char[] CHAR_LETTERS = StringUtilities.union(CHAR_LOWERS, CHAR_UPPERS);
	public final static char[] CHAR_ALPHANUMERICS = StringUtilities.union(CHAR_LETTERS, CHAR_DIGITS);
	
	
	/**
	 * Password character set, is alphanumerics (without l, i, I, o, O, and 0)
	 * selected specials like + (bad for URL encoding, | is like i and 1,
	 * etc...)
	 */
	public final static char[] CHAR_PASSWORD_LOWERS = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'j', 'k', 'm', 'n', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
	public final static char[] CHAR_PASSWORD_UPPERS = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' };
	public final static char[] CHAR_PASSWORD_DIGITS = { '2', '3', '4', '5', '6', '7', '8', '9' };
	public final static char[] CHAR_PASSWORD_SPECIALS = { '_', '.', '!', '@', '$', '*', '=', '-', '?' };
	public final static char[] CHAR_PASSWORD_LETTERS = StringUtilities.union( CHAR_PASSWORD_LOWERS, CHAR_PASSWORD_UPPERS );


	/**
	 * This method performs canonicalization on data received to ensure that it
	 * has been reduced to its most basic form before validation. For example,
	 * URL-encoded data received from ordinary "application/x-www-url-encoded"
	 * forms so that it may be validated properly.
	 * <p>
	 * Canonicalization is simply the operation of reducing a possibly encoded
	 * string down to its simplest form. This is important, because attackers
	 * frequently use encoding to change their input in a way that will bypass
	 * validation filters, but still be interpreted properly by the target of
	 * the attack. Note that data encoded more than once is not something that a
	 * normal user would generate and should be regarded as an attack.
	 * <P>
	 * For input that comes from an HTTP servlet request, there are generally
	 * two types of encoding to be concerned with. The first is
	 * "applicaton/x-www-url-encoded" which is what is typically used in most
	 * forms and URI's where characters are encoded in a %xy format. The other
	 * type of common character encoding is HTML entity encoding, which uses
	 * several formats:
	 * <P>
	 * <PRE>&lt;</PRE>,
	 * <PRE>&#117;</PRE>, and
	 * <PRE>&#x3a;</PRE>.
	 * <P>
	 * Note that all of these formats may possibly render properly in a
	 * browser without the trailing semicolon.
	 * <P>
	 * Double-encoding is a particularly thorny problem, as applying ordinary decoders
	 * may introduce encoded characters, even characters encoded with a different
	 * encoding scheme. For example %26lt; is a < character which has been entity encoded
	 * and then the first character has been url-encoded. Implementations should
	 * throw an IntrusionException when double-encoded characters are detected.
	 * <P>
	 * Note that there is also "multipart/form" encoding, which allows files and
	 * other binary data to be transmitted. Each part of a multipart form can
	 * itself be encoded according to a "Content-Transfer-Encoding" header. See
	 * the HTTPUtilties.getSafeFileUploads() method.
	 * <P>
	 * For more information on form encoding, please refer to the <a
	 * href="http://www.w3.org/TR/html4/interact/forms.html#h-17.13.4">W3C
	 * specifications</a>.
	 * 
	 * @param input the text to canonicalize
	 * @return a String containing the canonicalized text
	 * @throws EncodingException if canonicalization fails
	 */
	String canonicalize(String input) throws EncodingException;
	
	/**
	 * @param input 
	 * 		the text to canonicalize
	 * @param strict 
	 * 		true if checking for double encoding is desired, false otherwise
	 * 
	 * @return a String containing the canonicalized text
	 * 
	 * @throws EncodingException 
	 * 		if canonicalization fails
	 */
	String canonicalize(String input, boolean strict) throws EncodingException;

	/**
	 * Reduce all non-ascii characters to their ASCII form so that simpler
	 * validation rules can be applied. For example, an accented-e character
	 * will be changed into a regular ASCII e character.
	 * 
	 * @param input 
	 * 		the text to normalize
	 * 
	 * @return a normalized String
	 */
	String normalize(String input);

	/**
	 * Encode data for use in Cascading Style Sheets (CSS) content.
	 * 
	 * @param input 
	 * 		the text to encode for CSS
	 * 
	 * @return input encoded for CSS
	 */
	String encodeForCSS(String input);

	/**
	 * Encode data for use in HTML content.
	 * 
	 * @param input 
	 * 		the text to encode for HTML
	 * 
	 * @return input encoded for HTML
	 */
	String encodeForHTML(String input);

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
	 * Encode data for insertion inside a data value in a visual basic script. Putting user data directly
	 * inside a script is quite dangerous. Great care must be taken to prevent putting user data
	 * directly into script code itself, as no amount of encoding will prevent attacks there.
	 * 
	 * @param input 
	 * 		the text to encode for VBScript
	 * 
	 * @return input encoded for use in VBScript
	 */
	String encodeForVBScript(String input);


	/**
	 * Encode input for use in a SQL query (this method is not recommended), according to the
	 * selected codec (appropriate codecs include
	 * the MySQLCodec and OracleCodec).
	 * The use of the PreparedStatement interface is 
	 * and preferred approach. However, if for some reason this is impossible,
	 * then this method is provided as a weaker alternative. The best approach
	 * is to make sure any single-quotes are double-quoted. Another possible
	 * approach is to use the {escape} syntax described in the JDBC
	 * specification in section 1.5.6 (see
	 * http://java.sun.com/j2se/1.4.2/docs/guide/jdbc/getstart/statement.html).
	 * However, this syntax does not work with all drivers, and requires
	 * modification of all queries.
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
	 * 		a Codec that declares which database 'input' is being encoded for (ie. Windows, Unix, etc.)
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
	 * @param input 
	 * 		the text to encode for XPath
	 * 
	 * @return input encoded for use in XPath
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
	 * @param input
	 *            the text to encode for XML
	 * 
	 * @return input encoded for use in XML
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
	 * @param input
	 *            the text to encode for use as an XML attribute
	 * 
	 * @return input encoded for use in an XML attribute
	 */
	String encodeForXMLAttribute(String input);

	/**
	 * Encode for use in a URL. This method performs <a
	 * href="http://en.wikipedia.org/wiki/Percent-encoding">URL encoding"</a>
	 * on the entire string.
	 * 
	 * @param input 
	 * 		the text to encode for use in a URL
	 * 
	 * @return input encoded for use in a URL
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
	 * @return the decoded URL value
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
	 * @return input decoded from Base64
	 * 
	 * @throws IOException
	 */
	byte[] decodeFromBase64(String input) throws IOException;

}
