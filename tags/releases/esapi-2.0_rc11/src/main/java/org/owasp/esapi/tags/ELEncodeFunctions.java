package org.owasp.esapi.tags;

import java.io.UnsupportedEncodingException;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Encoder;
import org.owasp.esapi.errors.EncodingException;

/**
 * Static encoder methods for JSP EL expression functions.
 */
public class ELEncodeFunctions
{
	private static final String DEFAULT_ENCODING = "UTF-8";

	/**
	 * Private constructor as this class shouldn't need to be
	 * instantiated.
	 */
	private ELEncodeFunctions()
	{
	}

	/**
	 * Base64 encode a string. UTF-8 is used to encode the string and no line wrapping is performed.
	 * @param str The string to encode.
	 * @return The base64 encoded String.
	 * @see Encoder#encodeForBase64(byte[],boolean)
	 * @throws UnsupportedEncodingException if UTF-8 is an unsupported character set. This should not happen as UTF-8 is required to be supported by the JVM spec.
	 */
	public static String encodeForBase64(String str) throws UnsupportedEncodingException
	{
		return encodeForBase64Charset(DEFAULT_ENCODING, str);
	}

	/**
	 * Base64 encode a string with line wrapping. UTF-8 is used to encode the string and lines are wrapped at 64 characters..
	 * @param str The string to encode.
	 * @return The base64 encoded String.
	 * @see Encoder#encodeForBase64(byte[],boolean)
	 * @throws UnsupportedEncodingException if UTF-8 is an unsupported character set. This should not happen as UTF-8 is required to be supported by the JVM spec.
	 */
	public static String encodeForBase64Wrap(String str) throws UnsupportedEncodingException
	{
		return encodeForBase64CharsetWrap(DEFAULT_ENCODING, str);
	}

	/**
	 * Base64 encode a string after converting to bytes using the specified character set. No line wrapping is performed.
	 * @param charset The character set used to convert str to bytes.
	 * @param str The string to encode.
	 * @return The base64 encoded String.
	 * @see Encoder#encodeForBase64(byte[],boolean)
	 * @throws UnsupportedEncodingException if charset is an unsupported character set.
	 */
	public static String encodeForBase64Charset(String charset, String str) throws UnsupportedEncodingException
	{
		return ESAPI.encoder().encodeForBase64(str.getBytes(charset), false);
	}

	/**
	 * Base64 encode a string after converting to bytes using the specified character set and wrapping lines. Lines are wrapped at 64 characters.
	 * @param charset The character set used to convert str to bytes.
	 * @param str The string to encode.
	 * @return The base64 encoded String.
	 * @see Encoder#encodeForBase64(byte[],boolean)
	 * @throws UnsupportedEncodingException if charset is an unsupported character set.
	 */
	public static String encodeForBase64CharsetWrap(String charset, String str) throws UnsupportedEncodingException
	{
		return ESAPI.encoder().encodeForBase64(str.getBytes(charset), true);
	}

	/**
	 * Encode string for use in CSS.
	 * @param str The string to encode.
	 * @return str encoded for use in CSS.
	 * @see Encoder#encodeForCSS(String)
	 */
	public static String encodeForCSS(String str)
	{
		return ESAPI.encoder().encodeForCSS(str);
	}

	/**
	 * Encode string for use in HTML.
	 * @param str The string to encode.
	 * @return str encoded for use in HTML.
	 * @see Encoder#encodeForHTML(String)
	 */
	public static String encodeForHTML(String str)
	{
		return ESAPI.encoder().encodeForHTML(str);
	}

	/**
	 * Encode string for use in a HTML attribute.
	 * @param str The string to encode.
	 * @return str encoded for use in HTML attribute.
	 * @see Encoder#encodeForHTMLAttribute(String)
	 */
	public static String encodeForHTMLAttribute(String str)
	{
		return ESAPI.encoder().encodeForHTMLAttribute(str);
	}

	/**
	 * Encode string for use in JavaScript.
	 * @param str The string to encode.
	 * @return str encoded for use in JavaScript.
	 * @see Encoder#encodeForJavaScript(String)
	 */
	public static String encodeForJavaScript(String str)
	{
		return ESAPI.encoder().encodeForJavaScript(str);
	}

	/**
	 * Encode string for use in a URL.
	 * @param str The string to encode.
	 * @return str encoded for use in a URL.
	 * @see Encoder#encodeForURL(String)
	 */
	public static String encodeForURL(String str) throws EncodingException
	{
		return ESAPI.encoder().encodeForURL(str);
	}

	/**
	 * Encode string for use in VBScript.
	 * @param str The string to encode.
	 * @return str encoded for use in VBScript.
	 * @see Encoder#encodeForVBScript(String)
	 */
	public static String encodeForVBScript(String str)
	{
		return ESAPI.encoder().encodeForVBScript(str);
	}

	/**
	 * Encode string for use in XML.
	 * @param str The string to encode.
	 * @return str encoded for use in XML.
	 * @see Encoder#encodeForXML(String)
	 */
	public static String encodeForXML(String str)
	{
		return ESAPI.encoder().encodeForXML(str);
	}

	/**
	 * Encode string for use in a XML attribute.
	 * @param str The string to encode.
	 * @return str encoded for use in XML attribute.
	 * @see Encoder#encodeForXMLAttribute(String)
	 */
	public static String encodeForXMLAttribute(String str)
	{
		return ESAPI.encoder().encodeForXMLAttribute(str);
	}

	/**
	 * Encode string for use in XPath.
	 * @param str The string to encode.
	 * @return str encoded for use in XPath.
	 * @see Encoder#encodeForXPath(String)
	 */
	public static String encodeForXPath(String str)
	{
		return ESAPI.encoder().encodeForXPath(str);
	}
}
