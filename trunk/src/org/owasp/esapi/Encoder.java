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
	 * browser without the trailing semi-colon.
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
	 */
	String canonicalize(String input) throws EncodingException;
	
	String canonicalize(String input, boolean strict) throws EncodingException;

	/**
	 * Reduce all non-ascii characters to their ASCII form so that simpler
	 * validation rules can be applied. For example, an accented-e character
	 * will be changed into a regular ASCII e character.
	 */
	String normalize(String input);

	/**
	 * Encode data for use in Cascading Style Sheets (CSS) content.
	 */
	String encodeForCSS(String input);

	/**
	 * Encode data for use in HTML content.
	 */
	String encodeForHTML(String input);

	/**
	 * Encode data for use in HTML attributes.
	 */
	String encodeForHTMLAttribute(String input);

	/**
	 * Encode data for insertion inside a data value in a JavaScript. Putting user data directly
	 * inside a script is quite dangerous. Great care must be taken to prevent putting user data
	 * directly into script code itself, as no amount of encoding will prevent attacks there.
	 */
	String encodeForJavaScript(String input);

	/**
	 * Encode data for insertion inside a data value in a visual basic script. Putting user data directly
	 * inside a script is quite dangerous. Great care must be taken to prevent putting user data
	 * directly into script code itself, as no amount of encoding will prevent attacks there.
	 */
	String encodeForVBScript(String input);

	/**
	 * Encode for SQL according to the selected codec.
	 */
	String encodeForSQL(Codec codec, String input);

	/**
	 * Encode data for use in LDAP queries.
	 */
	String encodeForLDAP(String input);

	/**
	 * Encode data for use in an LDAP distinguished name. 
	 */
	String encodeForDN(String input);

	/**
	 * Encode data for use in an XPath query.
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
	 *            the input
	 * @return the string
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
	 *            the input
	 * @return the string
	 */
	String encodeForXMLAttribute(String input);

	/**
	 * Encode for use in a URL. This method performs <a
	 * href="http://en.wikipedia.org/wiki/Percent-encoding">URL encoding"</a>
	 * on the entire string.
	 */
	String encodeForURL(String input) throws EncodingException;

	/**
	 * Decode from URL. Implementations should first canonicalize and
	 * detect any double-encoding. If this check passes, then the data is decoded using URL
	 * decoding.
	 */
	String decodeFromURL(String input) throws EncodingException;

	/**
	 * Encode for Base64.
	 */
	String encodeForBase64(byte[] input, boolean wrap);

	/**
	 * Decode data encoded with BASE-64 encoding.
	 */
	byte[] decodeFromBase64(String input) throws IOException;

}
