/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * http://www.owasp.org/esapi.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the LGPL. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2007
 */
package org.owasp.esapi;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.Arrays;
import java.util.HashMap;

import org.owasp.esapi.errors.EncodingException;
import org.owasp.esapi.errors.IntrusionException;
import org.owasp.esapi.interfaces.ILogger;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;
import sun.text.Normalizer;

/**
 * Reference implementation of the IEncoder interface. This implementation takes
 * a whitelist approach, encoding everything not specifically identified in a
 * list of "immune" characters. Several methods follow the approach in the <a
 * href="http://www.microsoft.com/downloads/details.aspx?familyid=efb9c819-53ff-4f82-bfaf-e11625130c25&displaylang=en">Microsoft
 * AntiXSS Library</a>.
 * <p>
 * The canonicalization algorithm is complex, as it has to be able to recognize
 * encoded characters that might affect downstream interpreters without being
 * told what encodings are possible. The stream is read one character at a time.
 * If an encoded character is encountered, it is canonicalized and pushed back
 * onto the stream. If the next character is encoded, then a intrusion exception
 * is thrown for the double-encoding which is assumed to be an attack. This assumption is
 * a bit aggressive as some double-encoded characters may be sent by ordinary users
 * through cut-and-paste.
 * <p>
 * If an encoded character is recognized, but does not parse properly, the response is
 * to eat the character, stripping it from the input.
 * <p>
 * Currently the implementation supports:
 * <ul><li>HTML Entity Encoding (including non-terminated)</li><li>Percent Encoding</li></ul>
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 * @see org.owasp.esapi.interfaces.IEncoder
 */
public class Encoder implements org.owasp.esapi.interfaces.IEncoder {

	/** Encoding types */
	public static final int NO_ENCODING = 0;
	public static final int URL_ENCODING = 1;
	public static final int PERCENT_ENCODING = 2;
	public static final int ENTITY_ENCODING = 3;

	/** The base64 encoder. */
	private static final BASE64Encoder base64Encoder = new BASE64Encoder();

	/** The base64 decoder. */
	private static final BASE64Decoder base64Decoder = new BASE64Decoder();

	/** The IMMUNE HTML. */
	private final static char[] IMMUNE_HTML = { ',', '.', '-', '_', ' ' };

	/** The IMMUNE HTMLATTR. */
	private final static char[] IMMUNE_HTMLATTR = { ',', '.', '-', '_' };

	/** The IMMUNE JAVASCRIPT. */
	private final static char[] IMMUNE_JAVASCRIPT = { ',', '.', '-', '_', ' ' };

	/** The IMMUNE VBSCRIPT. */
	private final static char[] IMMUNE_VBSCRIPT = { ',', '.', '-', '_', ' ' };

	/** The IMMUNE XML. */
	private final static char[] IMMUNE_XML = { ',', '.', '-', '_', ' ' };

	/** The IMMUNE XMLATTR. */
	private final static char[] IMMUNE_XMLATTR = { ',', '.', '-', '_' };

	/** The IMMUNE XPATH. */
	private final static char[] IMMUNE_XPATH = { ',', '.', '-', '_', ' ' };

	/** The logger. */
	private static final ILogger logger = ESAPI.getLogger("Encoder");

	/** The Constant CHAR_LOWERS. */
	public final static char[] CHAR_LOWERS = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };

	/** The Constant CHAR_UPPERS. */
	public final static char[] CHAR_UPPERS = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' };

	/** The Constant CHAR_DIGITS. */
	public final static char[] CHAR_DIGITS = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' };

	/** The Constant CHAR_SPECIALS. */
	public final static char[] CHAR_SPECIALS = { '.', '-', '_', '!', '@', '$', '^', '*', '=', '~', '|', '+', '?' };

	/** The Constant CHAR_LETTERS. */
	public final static char[] CHAR_LETTERS = Randomizer.union(CHAR_LOWERS, CHAR_UPPERS);

	/** The Constant CHAR_ALPHANUMERICS. */
	public final static char[] CHAR_ALPHANUMERICS = Randomizer.union(CHAR_LETTERS, CHAR_DIGITS);

	// FIXME: ENHANCE make all character sets configurable
	/**
	 * Password character set, is alphanumerics (without l, i, I, o, O, and 0)
	 * selected specials like + (bad for URL encoding, | is like i and 1,
	 * etc...)
	 */
	final static char[] CHAR_PASSWORD_LOWERS = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'j', 'k', 'm', 'n', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
	final static char[] CHAR_PASSWORD_UPPERS = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' };
	final static char[] CHAR_PASSWORD_DIGITS = { '2', '3', '4', '5', '6', '7', '8', '9' };
	final static char[] CHAR_PASSWORD_SPECIALS = { '_', '.', '!', '@', '$', '*', '=', '-', '?' };
	public final static char[] CHAR_PASSWORD_LETTERS = Randomizer.union( CHAR_PASSWORD_LOWERS, CHAR_PASSWORD_UPPERS );

	private static HashMap characterToEntityMap;

	private static HashMap entityToCharacterMap;

	public Encoder() {
		Arrays.sort( Encoder.IMMUNE_HTML );
		Arrays.sort( Encoder.IMMUNE_HTMLATTR );
		Arrays.sort( Encoder.IMMUNE_JAVASCRIPT );
		Arrays.sort( Encoder.IMMUNE_VBSCRIPT );
		Arrays.sort( Encoder.IMMUNE_XML );
		Arrays.sort( Encoder.IMMUNE_XMLATTR );
		Arrays.sort( Encoder.IMMUNE_XPATH );
		Arrays.sort( Encoder.CHAR_LOWERS );
		Arrays.sort( Encoder.CHAR_UPPERS );
		Arrays.sort( Encoder.CHAR_DIGITS );
		Arrays.sort( Encoder.CHAR_SPECIALS );
		Arrays.sort( Encoder.CHAR_LETTERS );
		Arrays.sort( Encoder.CHAR_ALPHANUMERICS );
		Arrays.sort( Encoder.CHAR_PASSWORD_LOWERS );
		Arrays.sort( Encoder.CHAR_PASSWORD_UPPERS );
		Arrays.sort( Encoder.CHAR_PASSWORD_DIGITS );
		Arrays.sort( Encoder.CHAR_PASSWORD_SPECIALS );
		Arrays.sort( Encoder.CHAR_PASSWORD_LETTERS );
		initializeMaps();
	}

	/**
	 * Simplifies percent-encoded and entity-encoded characters to their
	 * simplest form so that they can be properly validated. Attackers
	 * frequently use encoding schemes to disguise their attacks and bypass
	 * validation routines.
	 * 
	 * Handling multiple encoding schemes simultaneously is difficult, and
	 * requires some special consideration. In particular, the problem of
	 * double-encoding is difficult for parsers, and combining several encoding
	 * schemes in double-encoding makes it even harder. Consider decoding
	 * 
	 * <PRE>
	 * &amp;lt;
	 * </PRE>
	 * 
	 * or
	 * 
	 * <PRE>
	 * %26lt;
	 * </PRE>
	 * 
	 * or
	 * 
	 * <PRE>
	 * &amp;lt;
	 * </PRE>.
	 * 
	 * This implementation disallows ALL double-encoded characters and throws an
	 * IntrusionException when they are detected. Also, named entities that are
	 * not known are simply removed.
	 * 
	 * Note that most data from the browser is likely to be encoded with URL
	 * encoding (FIXME: RFC). The web server will decode the URL and form data
	 * once, so most encoded data received in the application must have been
	 * double-encoded by the attacker. However, some HTTP inputs are not decoded
	 * by the browser, so this routine allows a single level of decoding.
	 * 
	 * @throws IntrusionException
	 * @see org.owasp.esapi.interfaces.IValidator#canonicalize(java.lang.String)
	 */
	public String canonicalize(String input) {
		StringBuffer sb = new StringBuffer();
		EncodedStringReader reader = new EncodedStringReader(input);
		while (reader.hasNext()) {
			EncodedCharacter c = reader.getNextCharacter();
			if (c != null) {
				sb.append(c.getUnencoded());
			}
		}
		return sb.toString();
	}

	/**
	 * Normalizes special characters down to ASCII using the Normalizer built
	 * into Java. Note that this method may introduce security issues if
	 * characters are normalized into special characters that have meaning
	 * to the destination of the data.
	 * 
	 * @see org.owasp.esapi.interfaces.IValidator#normalize(java.lang.String)
	 */
	public String normalize(String input) {
		// Split any special characters into two parts, the base character and
		// the modifier
		
        String separated = Normalizer.normalize(input, Normalizer.DECOMP, 0);  // Java 1.4
		// String separated = Normalizer.normalize(input, Form.NFD);   // Java 1.6

		// remove any character that is not ASCII
		return separated.replaceAll("[^\\p{ASCII}]", "");
	}

	/**
	 * Checks if the character is contained in the provided array of characters.
	 * 
	 * @param array
	 *            the array
	 * @param element
	 *            the element
	 * @return true, if is contained
	 */
	private boolean isContained(char[] array, char element) {
		for (int i = 0; i < array.length; i++) {
			if (element == array[i])
				return true;
		}
		return false;

		// FIXME: ENHANCE Performance enhancement here but character arrays must
		// be sorted, which they're currently not.
		// return( Arrays.binarySearch(array, element) >= 0 );
	}

	/**
	 * HTML Entity encode utility method. To avoid double-encoding, this method
	 * logs a warning if HTML entity encoded characters are passed in as input.
	 * Double-encoded characters in the input cause an exception to be thrown.
	 * 
	 * @param input
	 *            the input
	 * @param immune
	 *            the immune
	 * @param base
	 *            the base
	 * @return the string
	 */
	private String entityEncode(String input, char[] base, char[] immune) {
		
		// FIXME: Enhance - this may over-encode international data unnecessarily if charset is set properly.
		
		StringBuffer sb = new StringBuffer();
		EncodedStringReader reader = new EncodedStringReader(input);
		while (reader.hasNext()) {
			EncodedCharacter c = reader.getNextCharacter();
			if (c != null) {
				if (isContained(base, c.getUnencoded()) || isContained(immune, c.getUnencoded())) {
					sb.append(c.getUnencoded());
				} else {
					sb.append(c.getEncoded(ENTITY_ENCODING));
				}
			}
		}
		return sb.toString();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IEncoder#encodeForHTML(java.lang.String)
	 */
	public String encodeForHTML(String input) {
		// FIXME: ENHANCE - should this just strip out nonprintables? Why send
		// &#07; to the browser?
		// FIXME: Enhance - Add a configuration for masking **** out SSN and credit
		// card
		// FIXME: AAA - disallow everything below 20, except CR LF TAB
		//  See the SGML declaration - http://www.w3.org/TR/html4/sgml/sgmldecl.html
		//  See the XML specification - see http://www.w3.org/TR/REC-xml/#charsets
		// The question is how to proceed - strip or throw an exception?
		String encoded = entityEncode(input, Encoder.CHAR_ALPHANUMERICS, IMMUNE_HTML);
		encoded = encoded.replaceAll("\r", "<BR>");
		encoded = encoded.replaceAll("\n", "<BR>");
		return encoded;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IEncoder#encodeForHTMLAttribute(java.lang.String)
	 */
	public String encodeForHTMLAttribute(String input) {
		return entityEncode(input, Encoder.CHAR_ALPHANUMERICS, IMMUNE_HTMLATTR);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IEncoder#encodeForJavaScript(java.lang.String)
	 */
	public String encodeForJavascript(String input) {
		return entityEncode(input, Encoder.CHAR_ALPHANUMERICS, Encoder.IMMUNE_JAVASCRIPT);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IEncoder#encodeForVisualBasicScript(java.lang.String)
	 */
	public String encodeForVBScript(String input) {
		return entityEncode(input, Encoder.CHAR_ALPHANUMERICS, IMMUNE_VBSCRIPT);
	}

	/**
	 * This method is not recommended. The use PreparedStatement is the normal
	 * and preferred approach. However, if for some reason this is impossible,
	 * then this method is provided as a weaker alternative. The best approach
	 * is to make sure any single-quotes are double-quoted. Another possible
	 * approach is to use the {escape} syntax described in the JDBC
	 * specification in section 1.5.6 (see
	 * http://java.sun.com/j2se/1.4.2/docs/guide/jdbc/getstart/statement.html).
	 * However, this syntax does not work with all drivers, and requires
	 * modification of all queries.
	 * 
	 * @param input
	 *            the input
	 * @return the string
	 * @see org.owasp.esapi.interfaces.IEncoder#encodeForSQL(java.lang.String)
	 */
	public String encodeForSQL(String input) {
		String canonical = canonicalize(input);
		return canonical.replaceAll("'", "''");
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IEncoder#encodeForLDAP(java.lang.String)
	 */
	public String encodeForLDAP(String input) {
		String canonical = canonicalize(input);

		// FIXME: ENHANCE this is a negative list -- make positive?
		StringBuffer sb = new StringBuffer();
		for (int i = 0; i < canonical.length(); i++) {
			char c = canonical.charAt(i);
			switch (c) {
			case '\\':
				sb.append("\\5c");
				break;
			case '*':
				sb.append("\\2a");
				break;
			case '(':
				sb.append("\\28");
				break;
			case ')':
				sb.append("\\29");
				break;
			case '\u0000':
				sb.append("\\00");
				break;
			default:
				sb.append(c);
			}
		}
		return sb.toString();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IEncoder#encodeForDN(java.lang.String)
	 */
	public String encodeForDN(String input) {
		String canonical = canonicalize(input);

		StringBuffer sb = new StringBuffer();
		if ((canonical.length() > 0) && ((canonical.charAt(0) == ' ') || (canonical.charAt(0) == '#'))) {
			sb.append('\\'); // add the leading backslash if needed
		}
		for (int i = 0; i < canonical.length(); i++) {
			char c = canonical.charAt(i);
			switch (c) {
			case '\\':
				sb.append("\\\\");
				break;
			case ',':
				sb.append("\\,");
				break;
			case '+':
				sb.append("\\+");
				break;
			case '"':
				sb.append("\\\"");
				break;
			case '<':
				sb.append("\\<");
				break;
			case '>':
				sb.append("\\>");
				break;
			case ';':
				sb.append("\\;");
				break;
			default:
				sb.append(c);
			}
		}
		// add the trailing backslash if needed
		if ((canonical.length() > 1) && (canonical.charAt(canonical.length() - 1) == ' ')) {
			sb.insert(sb.length() - 1, '\\');
		}
		return sb.toString();
	}

	/**
	 * This implementation encodes almost everything and may overencode. The
	 * difficulty is that XPath has no built in mechanism for escaping
	 * characters. It is possible to use XQuery in a parameterized way to
	 * prevent injection. For more information, refer to <a
	 * href="http://www.ibm.com/developerworks/xml/library/x-xpathinjection.html">this
	 * article</a> which specifies the following list of characters as the most
	 * dangerous: ^&"*';<>(). <a
	 * href="http://www.packetstormsecurity.org/papers/bypass/Blind_XPath_Injection_20040518.pdf">This
	 * paper</a> suggests disallowing ' and " in queries.
	 * 
	 * @param input
	 *            the input
	 * @return the string
	 * @see org.owasp.esapi.interfaces.IEncoder#encodeForXPath(java.lang.String)
	 */
	public String encodeForXPath(String input) {
		return entityEncode(input, Encoder.CHAR_ALPHANUMERICS, IMMUNE_XPATH);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IEncoder#encodeForXML(java.lang.String)
	 */
	public String encodeForXML(String input) {
		return entityEncode(input, Encoder.CHAR_ALPHANUMERICS, IMMUNE_XML);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IEncoder#encodeForXMLAttribute(java.lang.String)
	 */
	public String encodeForXMLAttribute(String input) {
		return entityEncode(input, Encoder.CHAR_ALPHANUMERICS, IMMUNE_XMLATTR);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IEncoder#encodeForURL(java.lang.String)
	 */
	public String encodeForURL(String input) throws EncodingException {
		String canonical = canonicalize(input);

		try {
			return URLEncoder.encode(canonical, ESAPI.securityConfiguration().getCharacterEncoding());
		} catch (UnsupportedEncodingException ex) {
			throw new EncodingException("Encoding failure", "Encoding not supported", ex);
		} catch (Exception e) {
			throw new EncodingException("Encoding failure", "Problem URL decoding input", e);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IEncoder#decodeFromURL(java.lang.String)
	 */
	public String decodeFromURL(String input) throws EncodingException {
		String canonical = canonicalize(input);
		try {
			return URLDecoder.decode(canonical, ESAPI.securityConfiguration().getCharacterEncoding());
		} catch (UnsupportedEncodingException ex) {
			throw new EncodingException("Decoding failed", "Encoding not supported", ex);
		} catch (Exception e) {
			throw new EncodingException("Decoding failed", "Problem URL decoding input", e);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IEncoder#encodeForBase64(byte[])
	 */
	public String encodeForBase64(byte[] input, boolean wrap) {
		String b64 = base64Encoder.encode(input);
		// remove line-feeds and carriage-returns inserted in output
		if (!wrap) {
			b64 = b64.replaceAll("\r", "").replaceAll("\n", "");
		}
		return b64;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IEncoder#decodeFromBase64(java.lang.String)
	 */
	public byte[] decodeFromBase64(String input) throws IOException {
		return base64Decoder.decodeBuffer(input);
	}

	// FIXME: ENHANCE - change formatting here to more like -- "quot", "34", //
	// quotation mark
	private void initializeMaps() {
		String[] entityNames = { "quot"
		/* 34 : quotation mark */, "amp"
		/* 38 : ampersand */, "lt"
		/* 60 : less-than sign */, "gt"
		/* 62 : greater-than sign */, "nbsp"
		/* 160 : no-break space */, "iexcl"
		/* 161 : inverted exclamation mark */, "cent"
		/* 162 : cent sign */, "pound"
		/* 163 : pound sign */, "curren"
		/* 164 : currency sign */, "yen"
		/* 165 : yen sign */, "brvbar"
		/* 166 : broken bar */, "sect"
		/* 167 : section sign */, "uml"
		/* 168 : diaeresis */, "copy"
		/* 169 : copyright sign */, "ordf"
		/* 170 : feminine ordinal indicator */, "laquo"
		/* 171 : left-pointing double angle quotation mark */, "not"
		/* 172 : not sign */, "shy"
		/* 173 : soft hyphen */, "reg"
		/* 174 : registered sign */, "macr"
		/* 175 : macron */, "deg"
		/* 176 : degree sign */, "plusmn"
		/* 177 : plus-minus sign */, "sup2"
		/* 178 : superscript two */, "sup3"
		/* 179 : superscript three */, "acute"
		/* 180 : acute accent */, "micro"
		/* 181 : micro sign */, "para"
		/* 182 : pilcrow sign */, "middot"
		/* 183 : middle dot */, "cedil"
		/* 184 : cedilla */, "sup1"
		/* 185 : superscript one */, "ordm"
		/* 186 : masculine ordinal indicator */, "raquo"
		/* 187 : right-pointing double angle quotation mark */, "frac14"
		/* 188 : vulgar fraction one quarter */, "frac12"
		/* 189 : vulgar fraction one half */, "frac34"
		/* 190 : vulgar fraction three quarters */, "iquest"
		/* 191 : inverted question mark */, "Agrave"
		/* 192 : Latin capital letter a with grave */, "Aacute"
		/* 193 : Latin capital letter a with acute */, "Acirc"
		/* 194 : Latin capital letter a with circumflex */, "Atilde"
		/* 195 : Latin capital letter a with tilde */, "Auml"
		/* 196 : Latin capital letter a with diaeresis */, "Aring"
		/* 197 : Latin capital letter a with ring above */, "AElig"
		/* 198 : Latin capital letter ae */, "Ccedil"
		/* 199 : Latin capital letter c with cedilla */, "Egrave"
		/* 200 : Latin capital letter e with grave */, "Eacute"
		/* 201 : Latin capital letter e with acute */, "Ecirc"
		/* 202 : Latin capital letter e with circumflex */, "Euml"
		/* 203 : Latin capital letter e with diaeresis */, "Igrave"
		/* 204 : Latin capital letter i with grave */, "Iacute"
		/* 205 : Latin capital letter i with acute */, "Icirc"
		/* 206 : Latin capital letter i with circumflex */, "Iuml"
		/* 207 : Latin capital letter i with diaeresis */, "ETH"
		/* 208 : Latin capital letter eth */, "Ntilde"
		/* 209 : Latin capital letter n with tilde */, "Ograve"
		/* 210 : Latin capital letter o with grave */, "Oacute"
		/* 211 : Latin capital letter o with acute */, "Ocirc"
		/* 212 : Latin capital letter o with circumflex */, "Otilde"
		/* 213 : Latin capital letter o with tilde */, "Ouml"
		/* 214 : Latin capital letter o with diaeresis */, "times"
		/* 215 : multiplication sign */, "Oslash"
		/* 216 : Latin capital letter o with stroke */, "Ugrave"
		/* 217 : Latin capital letter u with grave */, "Uacute"
		/* 218 : Latin capital letter u with acute */, "Ucirc"
		/* 219 : Latin capital letter u with circumflex */, "Uuml"
		/* 220 : Latin capital letter u with diaeresis */, "Yacute"
		/* 221 : Latin capital letter y with acute */, "THORN"
		/* 222 : Latin capital letter thorn */, "szlig"
		/* 223 : Latin small letter sharp s, German Eszett */, "agrave"
		/* 224 : Latin small letter a with grave */, "aacute"
		/* 225 : Latin small letter a with acute */, "acirc"
		/* 226 : Latin small letter a with circumflex */, "atilde"
		/* 227 : Latin small letter a with tilde */, "auml"
		/* 228 : Latin small letter a with diaeresis */, "aring"
		/* 229 : Latin small letter a with ring above */, "aelig"
		/* 230 : Latin lowercase ligature ae */, "ccedil"
		/* 231 : Latin small letter c with cedilla */, "egrave"
		/* 232 : Latin small letter e with grave */, "eacute"
		/* 233 : Latin small letter e with acute */, "ecirc"
		/* 234 : Latin small letter e with circumflex */, "euml"
		/* 235 : Latin small letter e with diaeresis */, "igrave"
		/* 236 : Latin small letter i with grave */, "iacute"
		/* 237 : Latin small letter i with acute */, "icirc"
		/* 238 : Latin small letter i with circumflex */, "iuml"
		/* 239 : Latin small letter i with diaeresis */, "eth"
		/* 240 : Latin small letter eth */, "ntilde"
		/* 241 : Latin small letter n with tilde */, "ograve"
		/* 242 : Latin small letter o with grave */, "oacute"
		/* 243 : Latin small letter o with acute */, "ocirc"
		/* 244 : Latin small letter o with circumflex */, "otilde"
		/* 245 : Latin small letter o with tilde */, "ouml"
		/* 246 : Latin small letter o with diaeresis */, "divide"
		/* 247 : division sign */, "oslash"
		/* 248 : Latin small letter o with stroke */, "ugrave"
		/* 249 : Latin small letter u with grave */, "uacute"
		/* 250 : Latin small letter u with acute */, "ucirc"
		/* 251 : Latin small letter u with circumflex */, "uuml"
		/* 252 : Latin small letter u with diaeresis */, "yacute"
		/* 253 : Latin small letter y with acute */, "thorn"
		/* 254 : Latin small letter thorn */, "yuml"
		/* 255 : Latin small letter y with diaeresis */, "OElig"
		/* 338 : Latin capital ligature oe */, "oelig"
		/* 339 : Latin small ligature oe */, "Scaron"
		/* 352 : Latin capital letter s with caron */, "scaron"
		/* 353 : Latin small letter s with caron */, "Yuml"
		/* 376 : Latin capital letter y with diaeresis */, "fnof"
		/* 402 : Latin small letter f with hook */, "circ"
		/* 710 : modifier letter circumflex accent */, "tilde"
		/* 732 : small tilde */, "Alpha"
		/* 913 : Greek capital letter alpha */, "Beta"
		/* 914 : Greek capital letter beta */, "Gamma"
		/* 915 : Greek capital letter gamma */, "Delta"
		/* 916 : Greek capital letter delta */, "Epsilon"
		/* 917 : Greek capital letter epsilon */, "Zeta"
		/* 918 : Greek capital letter zeta */, "Eta"
		/* 919 : Greek capital letter eta */, "Theta"
		/* 920 : Greek capital letter theta */, "Iota"
		/* 921 : Greek capital letter iota */, "Kappa"
		/* 922 : Greek capital letter kappa */, "Lambda"
		/* 923 : Greek capital letter lambda */, "Mu"
		/* 924 : Greek capital letter mu */, "Nu"
		/* 925 : Greek capital letter nu */, "Xi"
		/* 926 : Greek capital letter xi */, "Omicron"
		/* 927 : Greek capital letter omicron */, "Pi"
		/* 928 : Greek capital letter pi */, "Rho"
		/* 929 : Greek capital letter rho */, "Sigma"
		/* 931 : Greek capital letter sigma */, "Tau"
		/* 932 : Greek capital letter tau */, "Upsilon"
		/* 933 : Greek capital letter upsilon */, "Phi"
		/* 934 : Greek capital letter phi */, "Chi"
		/* 935 : Greek capital letter chi */, "Psi"
		/* 936 : Greek capital letter psi */, "Omega"
		/* 937 : Greek capital letter omega */, "alpha"
		/* 945 : Greek small letter alpha */, "beta"
		/* 946 : Greek small letter beta */, "gamma"
		/* 947 : Greek small letter gamma */, "delta"
		/* 948 : Greek small letter delta */, "epsilon"
		/* 949 : Greek small letter epsilon */, "zeta"
		/* 950 : Greek small letter zeta */, "eta"
		/* 951 : Greek small letter eta */, "theta"
		/* 952 : Greek small letter theta */, "iota"
		/* 953 : Greek small letter iota */, "kappa"
		/* 954 : Greek small letter kappa */, "lambda"
		/* 955 : Greek small letter lambda */, "mu"
		/* 956 : Greek small letter mu */, "nu"
		/* 957 : Greek small letter nu */, "xi"
		/* 958 : Greek small letter xi */, "omicron"
		/* 959 : Greek small letter omicron */, "pi"
		/* 960 : Greek small letter pi */, "rho"
		/* 961 : Greek small letter rho */, "sigmaf"
		/* 962 : Greek small letter final sigma */, "sigma"
		/* 963 : Greek small letter sigma */, "tau"
		/* 964 : Greek small letter tau */, "upsilon"
		/* 965 : Greek small letter upsilon */, "phi"
		/* 966 : Greek small letter phi */, "chi"
		/* 967 : Greek small letter chi */, "psi"
		/* 968 : Greek small letter psi */, "omega"
		/* 969 : Greek small letter omega */, "thetasym"
		/* 977 : Greek theta symbol */, "upsih"
		/* 978 : Greek upsilon with hook symbol */, "piv"
		/* 982 : Greek pi symbol */, "ensp"
		/* 8194 : en space */, "emsp"
		/* 8195 : em space */, "thinsp"
		/* 8201 : thin space */, "zwnj"
		/* 8204 : zero width non-joiner */, "zwj"
		/* 8205 : zero width joiner */, "lrm"
		/* 8206 : left-to-right mark */, "rlm"
		/* 8207 : right-to-left mark */, "ndash"
		/* 8211 : en dash */, "mdash"
		/* 8212 : em dash */, "lsquo"
		/* 8216 : left single quotation mark */, "rsquo"
		/* 8217 : right single quotation mark */, "sbquo"
		/* 8218 : single low-9 quotation mark */, "ldquo"
		/* 8220 : left double quotation mark */, "rdquo"
		/* 8221 : right double quotation mark */, "bdquo"
		/* 8222 : double low-9 quotation mark */, "dagger"
		/* 8224 : dagger */, "Dagger"
		/* 8225 : double dagger */, "bull"
		/* 8226 : bullet */, "hellip"
		/* 8230 : horizontal ellipsis */, "permil"
		/* 8240 : per mille sign */, "prime"
		/* 8242 : prime */, "Prime"
		/* 8243 : double prime */, "lsaquo"
		/* 8249 : single left-pointing angle quotation mark */, "rsaquo"
		/* 8250 : single right-pointing angle quotation mark */, "oline"
		/* 8254 : overline */, "frasl"
		/* 8260 : fraction slash */, "euro"
		/* 8364 : euro sign */, "image"
		/* 8465 : black-letter capital i */, "weierp"
		/* 8472 : script capital p, Weierstrass p */, "real"
		/* 8476 : black-letter capital r */, "trade"
		/* 8482 : trademark sign */, "alefsym"
		/* 8501 : alef symbol */, "larr"
		/* 8592 : leftwards arrow */, "uarr"
		/* 8593 : upwards arrow */, "rarr"
		/* 8594 : rightwards arrow */, "darr"
		/* 8595 : downwards arrow */, "harr"
		/* 8596 : left right arrow */, "crarr"
		/* 8629 : downwards arrow with corner leftwards */, "lArr"
		/* 8656 : leftwards double arrow */, "uArr"
		/* 8657 : upwards double arrow */, "rArr"
		/* 8658 : rightwards double arrow */, "dArr"
		/* 8659 : downwards double arrow */, "hArr"
		/* 8660 : left right double arrow */, "forall"
		/* 8704 : for all */, "part"
		/* 8706 : partial differential */, "exist"
		/* 8707 : there exists */, "empty"
		/* 8709 : empty set */, "nabla"
		/* 8711 : nabla */, "isin"
		/* 8712 : element of */, "notin"
		/* 8713 : not an element of */, "ni"
		/* 8715 : contains as member */, "prod"
		/* 8719 : n-ary product */, "sum"
		/* 8721 : n-ary summation */, "minus"
		/* 8722 : minus sign */, "lowast"
		/* 8727 : asterisk operator */, "radic"
		/* 8730 : square root */, "prop"
		/* 8733 : proportional to */, "infin"
		/* 8734 : infinity */, "ang"
		/* 8736 : angle */, "and"
		/* 8743 : logical and */, "or"
		/* 8744 : logical or */, "cap"
		/* 8745 : intersection */, "cup"
		/* 8746 : union */, "int"
		/* 8747 : integral */, "there4"
		/* 8756 : therefore */, "sim"
		/* 8764 : tilde operator */, "cong"
		/* 8773 : congruent to */, "asymp"
		/* 8776 : almost equal to */, "ne"
		/* 8800 : not equal to */, "equiv"
		/* 8801 : identical to, equivalent to */, "le"
		/* 8804 : less-than or equal to */, "ge"
		/* 8805 : greater-than or equal to */, "sub"
		/* 8834 : subset of */, "sup"
		/* 8835 : superset of */, "nsub"
		/* 8836 : not a subset of */, "sube"
		/* 8838 : subset of or equal to */, "supe"
		/* 8839 : superset of or equal to */, "oplus"
		/* 8853 : circled plus */, "otimes"
		/* 8855 : circled times */, "perp"
		/* 8869 : up tack */, "sdot"
		/* 8901 : dot operator */, "lceil"
		/* 8968 : left ceiling */, "rceil"
		/* 8969 : right ceiling */, "lfloor"
		/* 8970 : left floor */, "rfloor"
		/* 8971 : right floor */, "lang"
		/* 9001 : left-pointing angle bracket */, "rang"
		/* 9002 : right-pointing angle bracket */, "loz"
		/* 9674 : lozenge */, "spades"
		/* 9824 : black spade suit */, "clubs"
		/* 9827 : black club suit */, "hearts"
		/* 9829 : black heart suit */, "diams"
		/* 9830 : black diamond suit */, };

		char[] entityValues = { 34
		/* &quot; : quotation mark */, 38
		/* &amp; : ampersand */, 60
		/* &lt; : less-than sign */, 62
		/* &gt; : greater-than sign */, 160
		/* &nbsp; : no-break space */, 161
		/* &iexcl; : inverted exclamation mark */, 162
		/* &cent; : cent sign */, 163
		/* &pound; : pound sign */, 164
		/* &curren; : currency sign */, 165
		/* &yen; : yen sign */, 166
		/* &brvbar; : broken bar */, 167
		/* &sect; : section sign */, 168
		/* &uml; : diaeresis */, 169
		/* &copy; : copyright sign */, 170
		/* &ordf; : feminine ordinal indicator */, 171
		/* &laquo; : left-pointing double angle quotation mark */, 172
		/* &not; : not sign */, 173
		/* &shy; : soft hyphen */, 174
		/* &reg; : registered sign */, 175
		/* &macr; : macron */, 176
		/* &deg; : degree sign */, 177
		/* &plusmn; : plus-minus sign */, 178
		/* &sup2; : superscript two */, 179
		/* &sup3; : superscript three */, 180
		/* &acute; : acute accent */, 181
		/* &micro; : micro sign */, 182
		/* &para; : pilcrow sign */, 183
		/* &middot; : middle dot */, 184
		/* &cedil; : cedilla */, 185
		/* &sup1; : superscript one */, 186
		/* &ordm; : masculine ordinal indicator */, 187
		/* &raquo; : right-pointing double angle quotation mark */, 188
		/* &frac14; : vulgar fraction one quarter */, 189
		/* &frac12; : vulgar fraction one half */, 190
		/* &frac34; : vulgar fraction three quarters */, 191
		/* &iquest; : inverted question mark */, 192
		/* &Agrave; : Latin capital letter a with grave */, 193
		/* &Aacute; : Latin capital letter a with acute */, 194
		/* &Acirc; : Latin capital letter a with circumflex */, 195
		/* &Atilde; : Latin capital letter a with tilde */, 196
		/* &Auml; : Latin capital letter a with diaeresis */, 197
		/* &Aring; : Latin capital letter a with ring above */, 198
		/* &AElig; : Latin capital letter ae */, 199
		/* &Ccedil; : Latin capital letter c with cedilla */, 200
		/* &Egrave; : Latin capital letter e with grave */, 201
		/* &Eacute; : Latin capital letter e with acute */, 202
		/* &Ecirc; : Latin capital letter e with circumflex */, 203
		/* &Euml; : Latin capital letter e with diaeresis */, 204
		/* &Igrave; : Latin capital letter i with grave */, 205
		/* &Iacute; : Latin capital letter i with acute */, 206
		/* &Icirc; : Latin capital letter i with circumflex */, 207
		/* &Iuml; : Latin capital letter i with diaeresis */, 208
		/* &ETH; : Latin capital letter eth */, 209
		/* &Ntilde; : Latin capital letter n with tilde */, 210
		/* &Ograve; : Latin capital letter o with grave */, 211
		/* &Oacute; : Latin capital letter o with acute */, 212
		/* &Ocirc; : Latin capital letter o with circumflex */, 213
		/* &Otilde; : Latin capital letter o with tilde */, 214
		/* &Ouml; : Latin capital letter o with diaeresis */, 215
		/* &times; : multiplication sign */, 216
		/* &Oslash; : Latin capital letter o with stroke */, 217
		/* &Ugrave; : Latin capital letter u with grave */, 218
		/* &Uacute; : Latin capital letter u with acute */, 219
		/* &Ucirc; : Latin capital letter u with circumflex */, 220
		/* &Uuml; : Latin capital letter u with diaeresis */, 221
		/* &Yacute; : Latin capital letter y with acute */, 222
		/* &THORN; : Latin capital letter thorn */, 223
		/* &szlig; : Latin small letter sharp s, German Eszett */, 224
		/* &agrave; : Latin small letter a with grave */, 225
		/* &aacute; : Latin small letter a with acute */, 226
		/* &acirc; : Latin small letter a with circumflex */, 227
		/* &atilde; : Latin small letter a with tilde */, 228
		/* &auml; : Latin small letter a with diaeresis */, 229
		/* &aring; : Latin small letter a with ring above */, 230
		/* &aelig; : Latin lowercase ligature ae */, 231
		/* &ccedil; : Latin small letter c with cedilla */, 232
		/* &egrave; : Latin small letter e with grave */, 233
		/* &eacute; : Latin small letter e with acute */, 234
		/* &ecirc; : Latin small letter e with circumflex */, 235
		/* &euml; : Latin small letter e with diaeresis */, 236
		/* &igrave; : Latin small letter i with grave */, 237
		/* &iacute; : Latin small letter i with acute */, 238
		/* &icirc; : Latin small letter i with circumflex */, 239
		/* &iuml; : Latin small letter i with diaeresis */, 240
		/* &eth; : Latin small letter eth */, 241
		/* &ntilde; : Latin small letter n with tilde */, 242
		/* &ograve; : Latin small letter o with grave */, 243
		/* &oacute; : Latin small letter o with acute */, 244
		/* &ocirc; : Latin small letter o with circumflex */, 245
		/* &otilde; : Latin small letter o with tilde */, 246
		/* &ouml; : Latin small letter o with diaeresis */, 247
		/* &divide; : division sign */, 248
		/* &oslash; : Latin small letter o with stroke */, 249
		/* &ugrave; : Latin small letter u with grave */, 250
		/* &uacute; : Latin small letter u with acute */, 251
		/* &ucirc; : Latin small letter u with circumflex */, 252
		/* &uuml; : Latin small letter u with diaeresis */, 253
		/* &yacute; : Latin small letter y with acute */, 254
		/* &thorn; : Latin small letter thorn */, 255
		/* &yuml; : Latin small letter y with diaeresis */, 338
		/* &OElig; : Latin capital ligature oe */, 339
		/* &oelig; : Latin small ligature oe */, 352
		/* &Scaron; : Latin capital letter s with caron */, 353
		/* &scaron; : Latin small letter s with caron */, 376
		/* &Yuml; : Latin capital letter y with diaeresis */, 402
		/* &fnof; : Latin small letter f with hook */, 710
		/* &circ; : modifier letter circumflex accent */, 732
		/* &tilde; : small tilde */, 913
		/* &Alpha; : Greek capital letter alpha */, 914
		/* &Beta; : Greek capital letter beta */, 915
		/* &Gamma; : Greek capital letter gamma */, 916
		/* &Delta; : Greek capital letter delta */, 917
		/* &Epsilon; : Greek capital letter epsilon */, 918
		/* &Zeta; : Greek capital letter zeta */, 919
		/* &Eta; : Greek capital letter eta */, 920
		/* &Theta; : Greek capital letter theta */, 921
		/* &Iota; : Greek capital letter iota */, 922
		/* &Kappa; : Greek capital letter kappa */, 923
		/* &Lambda; : Greek capital letter lambda */, 924
		/* &Mu; : Greek capital letter mu */, 925
		/* &Nu; : Greek capital letter nu */, 926
		/* &Xi; : Greek capital letter xi */, 927
		/* &Omicron; : Greek capital letter omicron */, 928
		/* &Pi; : Greek capital letter pi */, 929
		/* &Rho; : Greek capital letter rho */, 931
		/* &Sigma; : Greek capital letter sigma */, 932
		/* &Tau; : Greek capital letter tau */, 933
		/* &Upsilon; : Greek capital letter upsilon */, 934
		/* &Phi; : Greek capital letter phi */, 935
		/* &Chi; : Greek capital letter chi */, 936
		/* &Psi; : Greek capital letter psi */, 937
		/* &Omega; : Greek capital letter omega */, 945
		/* &alpha; : Greek small letter alpha */, 946
		/* &beta; : Greek small letter beta */, 947
		/* &gamma; : Greek small letter gamma */, 948
		/* &delta; : Greek small letter delta */, 949
		/* &epsilon; : Greek small letter epsilon */, 950
		/* &zeta; : Greek small letter zeta */, 951
		/* &eta; : Greek small letter eta */, 952
		/* &theta; : Greek small letter theta */, 953
		/* &iota; : Greek small letter iota */, 954
		/* &kappa; : Greek small letter kappa */, 955
		/* &lambda; : Greek small letter lambda */, 956
		/* &mu; : Greek small letter mu */, 957
		/* &nu; : Greek small letter nu */, 958
		/* &xi; : Greek small letter xi */, 959
		/* &omicron; : Greek small letter omicron */, 960
		/* &pi; : Greek small letter pi */, 961
		/* &rho; : Greek small letter rho */, 962
		/* &sigmaf; : Greek small letter final sigma */, 963
		/* &sigma; : Greek small letter sigma */, 964
		/* &tau; : Greek small letter tau */, 965
		/* &upsilon; : Greek small letter upsilon */, 966
		/* &phi; : Greek small letter phi */, 967
		/* &chi; : Greek small letter chi */, 968
		/* &psi; : Greek small letter psi */, 969
		/* &omega; : Greek small letter omega */, 977
		/* &thetasym; : Greek theta symbol */, 978
		/* &upsih; : Greek upsilon with hook symbol */, 982
		/* &piv; : Greek pi symbol */, 8194
		/* &ensp; : en space */, 8195
		/* &emsp; : em space */, 8201
		/* &thinsp; : thin space */, 8204
		/* &zwnj; : zero width non-joiner */, 8205
		/* &zwj; : zero width joiner */, 8206
		/* &lrm; : left-to-right mark */, 8207
		/* &rlm; : right-to-left mark */, 8211
		/* &ndash; : en dash */, 8212
		/* &mdash; : em dash */, 8216
		/* &lsquo; : left single quotation mark */, 8217
		/* &rsquo; : right single quotation mark */, 8218
		/* &sbquo; : single low-9 quotation mark */, 8220
		/* &ldquo; : left double quotation mark */, 8221
		/* &rdquo; : right double quotation mark */, 8222
		/* &bdquo; : double low-9 quotation mark */, 8224
		/* &dagger; : dagger */, 8225
		/* &Dagger; : double dagger */, 8226
		/* &bull; : bullet */, 8230
		/* &hellip; : horizontal ellipsis */, 8240
		/* &permil; : per mille sign */, 8242
		/* &prime; : prime */, 8243
		/* &Prime; : double prime */, 8249
		/* &lsaquo; : single left-pointing angle quotation mark */, 8250
		/* &rsaquo; : single right-pointing angle quotation mark */, 8254
		/* &oline; : overline */, 8260
		/* &frasl; : fraction slash */, 8364
		/* &euro; : euro sign */, 8465
		/* &image; : black-letter capital i */, 8472
		/* &weierp; : script capital p, Weierstrass p */, 8476
		/* &real; : black-letter capital r */, 8482
		/* &trade; : trademark sign */, 8501
		/* &alefsym; : alef symbol */, 8592
		/* &larr; : leftwards arrow */, 8593
		/* &uarr; : upwards arrow */, 8594
		/* &rarr; : rightwards arrow */, 8595
		/* &darr; : downwards arrow */, 8596
		/* &harr; : left right arrow */, 8629
		/* &crarr; : downwards arrow with corner leftwards */, 8656
		/* &lArr; : leftwards double arrow */, 8657
		/* &uArr; : upwards double arrow */, 8658
		/* &rArr; : rightwards double arrow */, 8659
		/* &dArr; : downwards double arrow */, 8660
		/* &hArr; : left right double arrow */, 8704
		/* &forall; : for all */, 8706
		/* &part; : partial differential */, 8707
		/* &exist; : there exists */, 8709
		/* &empty; : empty set */, 8711
		/* &nabla; : nabla */, 8712
		/* &isin; : element of */, 8713
		/* &notin; : not an element of */, 8715
		/* &ni; : contains as member */, 8719
		/* &prod; : n-ary product */, 8721
		/* &sum; : n-ary summation */, 8722
		/* &minus; : minus sign */, 8727
		/* &lowast; : asterisk operator */, 8730
		/* &radic; : square root */, 8733
		/* &prop; : proportional to */, 8734
		/* &infin; : infinity */, 8736
		/* &ang; : angle */, 8743
		/* &and; : logical and */, 8744
		/* &or; : logical or */, 8745
		/* &cap; : intersection */, 8746
		/* &cup; : union */, 8747
		/* &int; : integral */, 8756
		/* &there4; : therefore */, 8764
		/* &sim; : tilde operator */, 8773
		/* &cong; : congruent to */, 8776
		/* &asymp; : almost equal to */, 8800
		/* &ne; : not equal to */, 8801
		/* &equiv; : identical to, equivalent to */, 8804
		/* &le; : less-than or equal to */, 8805
		/* &ge; : greater-than or equal to */, 8834
		/* &sub; : subset of */, 8835
		/* &sup; : superset of */, 8836
		/* &nsub; : not a subset of */, 8838
		/* &sube; : subset of or equal to */, 8839
		/* &supe; : superset of or equal to */, 8853
		/* &oplus; : circled plus */, 8855
		/* &otimes; : circled times */, 8869
		/* &perp; : up tack */, 8901
		/* &sdot; : dot operator */, 8968
		/* &lceil; : left ceiling */, 8969
		/* &rceil; : right ceiling */, 8970
		/* &lfloor; : left floor */, 8971
		/* &rfloor; : right floor */, 9001
		/* &lang; : left-pointing angle bracket */, 9002
		/* &rang; : right-pointing angle bracket */, 9674
		/* &loz; : lozenge */, 9824
		/* &spades; : black spade suit */, 9827
		/* &clubs; : black club suit */, 9829
		/* &hearts; : black heart suit */, 9830
		/* &diams; : black diamond suit */, };
		characterToEntityMap = new HashMap(entityNames.length);
		entityToCharacterMap = new HashMap(entityValues.length);
		for (int i = 0; i < entityNames.length; i++) {
			String e = entityNames[i];
			Character c = new Character(entityValues[i]);
			entityToCharacterMap.put(e, c);
			characterToEntityMap.put(c, e);
		}
	}

	public static void main(String[] args) {
		// Encoder encoder = new Encoder();
		// try { System.out.println( ">>" + encoder.encodeForHTML("test <>
		// test") ); } catch( Exception e1 ) { System.out.println(" !" +
		// e1.getMessage() ); }
		// try { System.out.println( ">>" + encoder.encodeForHTML("test %41 %42
		// test") ); } catch( Exception e2 ) { System.out.println(" !" +
		// e2.getMessage() ); }
		// try { System.out.println( ">>" + encoder.encodeForHTML("test %26%42
		// test") ); } catch( Exception e2 ) { System.out.println(" !" +
		// e2.getMessage() ); }
		// try { System.out.println( ">>" + encoder.encodeForHTML("test %26amp;
		// test") ); } catch( Exception e3 ) { System.out.println(" !" +
		// e3.getMessage() ); }
		// try { System.out.println( ">>" + encoder.encodeForHTML("test &#38;
		// test") ); } catch( Exception e4 ) { System.out.println(" !" +
		// e4.getMessage() ); }
		// try { System.out.println( ">>" + encoder.encodeForHTML("test
		// &#38;amp; test") ); } catch( Exception e5 ) { System.out.println(" !"
		// + e5.getMessage() ); }
		// try { System.out.println( ">>" + encoder.encodeForHTML("test &#ridi;
		// test") ); } catch( Exception e6 ) { e6.printStackTrace() ; }
		//try {
		//	System.out.println(">>" + encoder.encodeForHTML("test &#01;&#02;&#03;&#04; test"));
		//} catch (Exception e7) {
		//	System.out.println("   !" + e7.getMessage());
		//}
	}

	private class EncodedStringReader {

		String input = null;
		int nextCharacter = 0;
		int testCharacter = 0;

		public EncodedStringReader(String input) {
			// System.out.println( "***" + input );
			if (input == null) {
				this.input = "";
			} else {
				this.input = input;
			}
		}

		public boolean hasNext() {
			return nextCharacter < input.length();
		}

		public EncodedCharacter getNextCharacter() {

			// get the current character and move past it
			testCharacter = nextCharacter;
			EncodedCharacter c = null;
			c = peekNextCharacter(input.charAt(nextCharacter));
			// System.out.println( nextCharacter + ":" + (int)c.getUnencoded() +
			// " -> " + testCharacter );
			nextCharacter = testCharacter;
			if (c == null)
				return null;

			// if the current character is encoded, check for double-encoded
			// characters
			if (c.isEncoded()) {
				testCharacter--;
				EncodedCharacter next = peekNextCharacter(c.getUnencoded());
				if (next != null) {
					if (next.isEncoded()) {
						throw new IntrusionException("Validation error", "Input contains double encoded characters.");
					} else {
						// System.out.println("Not double-encoded");
					}
				}
			}
			return c;
		}

		private EncodedCharacter peekNextCharacter(char currentCharacter) {
			// if we're on the last character
			if (testCharacter == input.length() - 1) {
				testCharacter++;
				return new EncodedCharacter(currentCharacter);
			} else if (currentCharacter == '&') {
				// if parsing an entity returns null - then we should skip it by
				// returning null here
				EncodedCharacter encoded = parseEntity(input, testCharacter);
				return encoded;
			} else if (currentCharacter == '%') {
				// if parsing a % encoded character returns null, then just
				// return the % and keep going
				EncodedCharacter encoded = parsePercent(input, testCharacter);
				if (encoded != null) {
					return encoded;
				}
				// FIXME: AAA add UTF-7 decoding
				// FIXME: others?
			}
			testCharacter++;
			return new EncodedCharacter(currentCharacter);
		}

		// return a character or null if no good character can be parsed.
		public EncodedCharacter parsePercent(String s, int startIndex) {
			// FIXME: AAA check if these can be longer than 2 characters?
			// consume as many as possible?
			String possible = s.substring(startIndex + 1, startIndex + 3);
			try {
				int c = Integer.parseInt(possible, 16);
				testCharacter += 3;
				return new EncodedCharacter("%" + possible, (char) c, PERCENT_ENCODING);
			} catch (NumberFormatException e) {
				// System.out.println("Found % but there was no encoded character following it");
				return null;
			}
		}

		/**
		 * Return a character or null if no good character can be parsed. Badly
		 * formed characters that simply can't be parsed are dropped, such as
		 * &#ridi; for which there is no reasonable translation. Characters that
		 * aren't terminated by a semicolon are also dropped. Note that this is
		 * legal html
		 * 
		 * <PRE>
		 * &lt;body onload=&quot;&amp;#x61ler&amp;#116('xss body')&quot;&gt;
		 * </PRE>
		 */
		public EncodedCharacter parseEntity(String s, int startIndex) {
			// FIXME: AAA - figure out how to handle non-semicolon terminated
			// characters
			int semiIndex = input.indexOf(";", startIndex + 1);
			if (semiIndex != -1) {
				if (semiIndex - startIndex <= 8) {
					String possible = input.substring(startIndex + 1, semiIndex).toLowerCase();
					// System.out.println( " " + possible + " -> " +
					// testCharacter );
					Character entity = (Character) entityToCharacterMap.get(possible);
					if (entity != null) {
						testCharacter += possible.length() + 2;
						return new EncodedCharacter("&" + possible + ";", entity.charValue(), ENTITY_ENCODING);
					} else if (possible.charAt(0) == '#') {
						// advance past this either way
						testCharacter += possible.length() + 2;
						try {
							// FIXME: Enhance - consider supporting #x encoding
							int c = Integer.parseInt(possible.substring(1));
							return new EncodedCharacter("&#" + (char) c + ";", (char) c, ENTITY_ENCODING);
						} catch (NumberFormatException e) {
							// invalid character - return null
							logger.warning(Logger.SECURITY, "Invalid numeric entity encoding &" + possible + ";");
						}
					}
				}
			}
			// System.out.println("Found & but there was no entity following it");
			testCharacter++;
			return new EncodedCharacter("&", '&', NO_ENCODING);
		}
	}

	private class EncodedCharacter {

		String raw = ""; // the core of the encoded representation (without
							// the prefix or suffix)
		char character = 0;
		int originalEncoding;

		public EncodedCharacter(char character) {
			this.raw = "" + character;
			this.character = character;
		}

		public boolean isEncoded() {
			return (raw.length() != 1);
		}

		public EncodedCharacter(String raw, char character, int originalEncoding) {
			this.raw = raw;
			this.character = character;
			this.originalEncoding = originalEncoding;
		}

		public char getUnencoded() {
			return character;
		}

		public String getEncoded(int encoding) {
			switch (encoding) {
			case Encoder.NO_ENCODING:
				return "" + character;
			case Encoder.URL_ENCODING:
				// FIXME: look up rules
				if (Character.isWhitespace(character))
					return "+";
				if (Character.isLetterOrDigit(character))
					return "" + character;
				return "%" + (int) character;
			case Encoder.PERCENT_ENCODING:
				return "%" + (int) character;
			case Encoder.ENTITY_ENCODING:
				String entityName = (String) characterToEntityMap.get(new Character(character));
				if (entityName != null)
					return "&" + entityName + ";";
				return "&#" + (int) character + ";";
			default:
				return null;
			}
		}
	}

}