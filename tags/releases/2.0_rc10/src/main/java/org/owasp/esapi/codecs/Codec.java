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
package org.owasp.esapi.codecs;


/**
 * The Codec interface defines a set of methods for encoding and decoding application level encoding schemes,
 * such as HTML entity encoding and percent encoding (aka URL encoding). Codecs are used in output encoding
 * and canonicalization.  The design of these codecs allows for character-by-character decoding, which is
 * necessary to detect double-encoding and the use of multiple encoding schemes, both of which are techniques
 * used by attackers to bypass validation and bury encoded attacks in data.
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 * @see org.owasp.esapi.Encoder
 */
public abstract class Codec {

	/**
	 * Initialize an array to mark which characters are to be encoded. Store the hex
	 * string for that character to save time later. If the character shouldn't be
	 * encoded, then store null.
	 */
	private static final String[] hex = new String[256];

	static {
		for ( char c = 0; c < 0xFF; c++ ) {
			if ( c >= 0x30 && c <= 0x39 || c >= 0x41 && c <= 0x5A || c >= 0x61 && c <= 0x7A ) {
				hex[c] = null;
			} else {
				hex[c] = toHex(c).intern();
			}
		}
	}


	/**
	 * Default constructor
	 */
	public Codec() {
	}

	/**
	 * Encode a String so that it can be safely used in a specific context.
	 * 
	 * @param immune
	 * @param input
	 * 		the String to encode
	 * @return the encoded String
	 */
	public String encode(char[] immune, String input) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < input.length(); i++) {
			char c = input.charAt(i);
			sb.append(encodeCharacter(immune, c));
		}
		return sb.toString();
	}

	/**
	 * Default implementation that should be overridden in specific codecs.
	 * 
	 * @param immune
	 * @param c
	 * 		the Character to encode
	 * @return
	 * 		the encoded Character
	 */
	public String encodeCharacter( char[] immune, Character c ) {
		return ""+c;
	}

	/**
	 * Decode a String that was encoded using the encode method in this Class
	 * 
	 * @param input
	 * 		the String to decode
	 * @return
	 *		the decoded String
	 */
	public String decode(String input) {
		StringBuilder sb = new StringBuilder();
		PushbackString pbs = new PushbackString(input);
		while (pbs.hasNext()) {
			Character c = decodeCharacter(pbs);
			if (c != null) {
				sb.append(c);
			} else {
				sb.append(pbs.next());
			}
		}
		return sb.toString();
	}

	/**
	 * Returns the decoded version of the next character from the input string and advances the
	 * current character in the PushbackString.  If the current character is not encoded, this 
	 * method MUST reset the PushbackString.
	 * 
	 * @param input	the Character to decode
	 * 
	 * @return the decoded Character
	 */
	public Character decodeCharacter( PushbackString input ) {
		return input.next();
	}

	/**
	 * Lookup the hex value of any character that is not alphanumeric.
	 * @param c The character to lookup.
	 * @return, return null if alphanumeric or the character code
	 * 	in hex.
	 */
	public static String getHexForNonAlphanumeric(char c)
	{
		if(c<0xFF)
			return hex[c];
		return toHex(c);
	}

	public static String toOctal(char c)
	{
		return Integer.toOctalString(c);
	}

	public static String toHex(char c)
	{
		return Integer.toHexString(c);
	}

	/**
	 * Utility to search a char[] for a specific char.
	 * 
	 * @param c
	 * @param array
	 * @return
	 */
	public static boolean containsCharacter( char c, char[] array ) {
		for (char ch : array) {
			if (c == ch) return true;
		}
		return false;
	}

}
