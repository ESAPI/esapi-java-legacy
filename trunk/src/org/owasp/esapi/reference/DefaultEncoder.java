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
package org.owasp.esapi.reference;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Logger;
import org.owasp.esapi.codecs.Base64;
import org.owasp.esapi.codecs.Codec;
import org.owasp.esapi.codecs.HTMLEntityCodec;
import org.owasp.esapi.codecs.PercentCodec;
import org.owasp.esapi.codecs.PushbackString;
import org.owasp.esapi.errors.EncodingException;
import org.owasp.esapi.errors.IntrusionException;

import sun.text.Normalizer;

/**
 * Reference implementation of the Encoder interface. This implementation takes
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
 * @see org.owasp.esapi.Encoder
 */
public class DefaultEncoder implements org.owasp.esapi.Encoder {

	// Codecs
	List codecs = new ArrayList();

	/** Encoding types */
	public static final int NO_ENCODING = 0;
	public static final int URL_ENCODING = 1;
	public static final int PERCENT_ENCODING = 2;
	public static final int ENTITY_ENCODING = 3;

	/** The base64 encoder. */
	//private final BASE64Encoder base64Encoder = new BASE64Encoder();
	
	/** The base64 decoder. */
	//private final BASE64Decoder base64Decoder = new BASE64Decoder();

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
	private final Logger logger = ESAPI.getLogger("Encoder");

	/** The Constant CHAR_LOWERS. */
	public final static char[] CHAR_LOWERS = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };

	/** The Constant CHAR_UPPERS. */
	public final static char[] CHAR_UPPERS = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' };

	/** The Constant CHAR_DIGITS. */
	public final static char[] CHAR_DIGITS = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' };

	/** The Constant CHAR_SPECIALS. */
	public final static char[] CHAR_SPECIALS = { '.', '-', '_', '!', '@', '$', '^', '*', '=', '~', '|', '+', '?' };

	/** The Constant CHAR_LETTERS. */
	public final static char[] CHAR_LETTERS = union(CHAR_LOWERS, CHAR_UPPERS);

	/** The Constant CHAR_ALPHANUMERICS. */
	public final static char[] CHAR_ALPHANUMERICS = union(CHAR_LETTERS, CHAR_DIGITS);

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
	public final static char[] CHAR_PASSWORD_LETTERS = union( CHAR_PASSWORD_LOWERS, CHAR_PASSWORD_UPPERS );

	public DefaultEncoder() {
		codecs.add( new HTMLEntityCodec() );
		codecs.add( new PercentCodec() );
		
		Arrays.sort( DefaultEncoder.IMMUNE_HTML );
		Arrays.sort( DefaultEncoder.IMMUNE_HTMLATTR );
		Arrays.sort( DefaultEncoder.IMMUNE_JAVASCRIPT );
		Arrays.sort( DefaultEncoder.IMMUNE_VBSCRIPT );
		Arrays.sort( DefaultEncoder.IMMUNE_XML );
		Arrays.sort( DefaultEncoder.IMMUNE_XMLATTR );
		Arrays.sort( DefaultEncoder.IMMUNE_XPATH );
		Arrays.sort( DefaultEncoder.CHAR_LOWERS );
		Arrays.sort( DefaultEncoder.CHAR_UPPERS );
		Arrays.sort( DefaultEncoder.CHAR_DIGITS );
		Arrays.sort( DefaultEncoder.CHAR_SPECIALS );
		Arrays.sort( DefaultEncoder.CHAR_LETTERS );
		Arrays.sort( DefaultEncoder.CHAR_ALPHANUMERICS );
		Arrays.sort( DefaultEncoder.CHAR_PASSWORD_LOWERS );
		Arrays.sort( DefaultEncoder.CHAR_PASSWORD_UPPERS );
		Arrays.sort( DefaultEncoder.CHAR_PASSWORD_DIGITS );
		Arrays.sort( DefaultEncoder.CHAR_PASSWORD_SPECIALS );
		Arrays.sort( DefaultEncoder.CHAR_PASSWORD_LETTERS );
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
	 * encoding (RFC 3986). The web server will decode the URL and form data
	 * once, so most encoded data received in the application must have been
	 * double-encoded by the attacker. However, some HTTP inputs are not decoded
	 * by the browser, so this routine allows a single level of decoding.
	 * 
	 * @throws IntrusionException
	 * @see org.owasp.esapi.Validator#canonicalize(java.lang.String)
	 */
	public String canonicalize( String input ) {
		if ( input == null ) return null;
		StringBuffer sb = new StringBuffer();
		PushbackString pbs = new PushbackString( input );
		boolean last = false;
		while ( pbs.hasNext() ) {
			// test for encoded character and pushback if found
			boolean found = decodeAttempt( pbs );

			// get the next character and do something with it
			Character ch = pbs.next();
			
			// if a decoded character is found, push it back
			if ( found ) {
				// if double encoding throw exception
				if ( last ) {
					throw new IntrusionException( "Input validation failure", "Double encoding detected in " + input );
				}
				pbs.pushback( ch );
				last = true;
				
			// otherwise just append the character
			} else {
				sb.append( ch );
				last = false;
			}
		}
		return sb.toString();
	}
	
	private boolean decodeAttempt( PushbackString pbs ) {
		Iterator i = codecs.iterator();
		pbs.mark();
		while ( i.hasNext() ) {
			pbs.reset();
			Codec codec = (Codec)i.next();
			Character decoded = codec.getDecodedCharacter(pbs);
			if ( decoded != null ) {
				pbs.pushback( decoded );
				return true;
			}
		}
		pbs.reset();
		return false;
	}


	/**
	 * Normalizes special characters down to ASCII using the Normalizer built
	 * into Java. Note that this method may introduce security issues if
	 * characters are normalized into special characters that have meaning
	 * to the destination of the data.
	 * 
	 * @see org.owasp.esapi.Validator#normalize(java.lang.String)
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
		HTMLEntityCodec codec = new HTMLEntityCodec();
		StringBuffer sb = new StringBuffer();
		PushbackString psb = new PushbackString( input );
		
		// EncodedStringReader reader = new EncodedStringReader(input);
		while (psb.hasNext()) {
			// get decoded characters to prevent double encoding
			psb.mark();
			Character c = codec.getDecodedCharacter( psb );
			if (c == null) {
				psb.reset();
				c = psb.next();
			}
			if (isContained(base, c.charValue()) || isContained(immune, c.charValue())) {
				sb.append( c );
			} else {
				sb.append( codec.encode( c ) );
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
		String encoded = entityEncode(input, DefaultEncoder.CHAR_ALPHANUMERICS, IMMUNE_HTML);
		
		// FIXME: AAA this handling is broken - some systems use CRLF as a single terminator 
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
		return entityEncode(input, DefaultEncoder.CHAR_ALPHANUMERICS, IMMUNE_HTMLATTR);
	}

	
	//FIXME
	public String encodeForHTMLURI(String input) {
		return null;
	}

	//FIXME
	public String encodeForCSS(String input) {
		return null;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IEncoder#encodeForJavaScript(java.lang.String)
	 */
	public String encodeForJavascript(String input) {
	    if(null == input) {
	        return null;
	    }

	    StringBuffer buf = new StringBuffer(input.length() + 2);
	    int len = input.length();

	    for(int x = 0; x < len; x++) {
// FIXME	        int value = input.codePointAt(x);
	    	int value = (int)input.charAt(x);
	        if(isJavaScriptStringSafe(value)) {
// FIXME	            buf.append(Character.toChars(value));
	        } else {
	            switch (value) {
	                case 0x0A: // newline
	                    buf.append("\\n");
	                    break;

	                case 0x09: // tab
	                    buf.append("\\t");
	                    break;

	                case 0x22: // Double-quote
	                    buf.append("\\\"");
	                    break;

	                case 0x27: // single-quote
	                    buf.append("\\'");
	                    break;

	                case 0x5C: // backslash
	                    buf.append("\\\\");
	                    break;

	                default:
// FIXME	                    buf.append(String.format("\\u%1$04X", value));
	            }
	        }
	    }

	    return buf.toString();
	}

	private static final String javaScriptStringSafeOther = ".,;: ()?!_-+*&{}[]@#";

	private static boolean isJavaScriptStringSafe(int codepoint) {
// FIXME: cast to character is wrong
	    if(Character.isLetterOrDigit((char)codepoint))
	        return true;

	    int len = javaScriptStringSafeOther.length();
	    // Check the whitelisted special characters
	    for(int x = 0; x < len; x++)
// FIXME:	        if(codepoint == javaScriptStringSafeOther.codePointAt(x))
	    	if ( codepoint == javaScriptStringSafeOther.charAt(x))
	            return true;

	    return false;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IEncoder#encodeForVisualBasicScript(java.lang.String)
	 */
	public String encodeForVBScript(String input) {
		return entityEncode(input, DefaultEncoder.CHAR_ALPHANUMERICS, IMMUNE_VBSCRIPT);
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
	 * @see org.owasp.esapi.Encoder#encodeForSQL(java.lang.String)
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
	 * @see org.owasp.esapi.Encoder#encodeForXPath(java.lang.String)
	 */
	public String encodeForXPath(String input) {
		return entityEncode(input, DefaultEncoder.CHAR_ALPHANUMERICS, IMMUNE_XPATH);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IEncoder#encodeForXML(java.lang.String)
	 */
	public String encodeForXML(String input) {
		return entityEncode(input, DefaultEncoder.CHAR_ALPHANUMERICS, IMMUNE_XML);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IEncoder#encodeForXMLAttribute(java.lang.String)
	 */
	public String encodeForXMLAttribute(String input) {
		return entityEncode(input, DefaultEncoder.CHAR_ALPHANUMERICS, IMMUNE_XMLATTR);
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
		int options = 0;
		if ( !wrap ) {
			options |= Base64.DONT_BREAK_LINES;
		}
		return Base64.encodeBytes(input, options);
		
		// String b64 = base64Encoder.encode(input);
		// remove line-feeds and carriage-returns inserted in output
		// if (!wrap) {
		// 	b64 = b64.replaceAll("\r", "").replaceAll("\n", "");
		// }
		// return b64;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IEncoder#decodeFromBase64(java.lang.String)
	 */
	public byte[] decodeFromBase64(String input) throws IOException {
		// return base64Decoder.decodeBuffer(input);
		return Base64.decode( input );
	}

    /**
     * Union two character arrays.
     * 
     * @param c1 the c1
     * @param c2 the c2
     * @return the char[]
     */
    private static char[] union(char[] c1, char[] c2) {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < c1.length; i++) {
            if (!contains(sb, c1[i]))
                sb.append(c1[i]);
        }
        for (int i = 0; i < c2.length; i++) {
            if (!contains(sb, c2[i]))
                sb.append(c2[i]);
        }
        char[] c3 = new char[sb.length()];
        sb.getChars(0, sb.length(), c3, 0);
        Arrays.sort(c3);
        return c3;
    }

    /**
     * Contains.
     * 
     * @param sb the sb
     * @param c the c
     * @return true, if successful
     */
    private static boolean contains(StringBuffer sb, char c) {
        for (int i = 0; i < sb.length(); i++) {
            if (sb.charAt(i) == c)
                return true;
        }
        return false;
    }
}