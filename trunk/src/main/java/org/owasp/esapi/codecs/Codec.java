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

	protected static String[] hex = new String[256];
	
	/**
	 * Default constructor
	 */
	public Codec() {
		for ( int c = 0; c < 0xFF; c++ ) {
			if ( c >= 0x30 && c <= 0x39 || c >= 0x41 && c <= 0x5A || c >= 0x61 && c <= 0x7A ) {
				hex[c] = null;
			} else {
				hex[c] = Integer.toHexString(c);
			}
		}
	}
	
	/**
	 * Encode a String so that it can be safely used in a specific context.
	 * 
	 * @param input
	 * 		the String to encode
	 * @return the encoded String
	 */
    public String encode(char[] immune, String input) {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            sb.append(encodeCharacter(immune, new Character(c)));
        }
        return sb.toString();
    }

	
	/**
	 * Default implementation that should be overridden in specific codecs.
	 * 
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
        StringBuffer sb = new StringBuffer();
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
	 * Lookup the hex value of any character that is not alphanumeric, return null if alphanumeric.
	 */
	public static String getHex( char c ) {
		return hex[(int)c];
	}

	/**
	 * Utility to search a char[] for a specific char.
	 * 
	 * @param c
	 * @param array
	 * @return
	 */
	public static boolean containsCharacter( char c, char[] array ) {
		for (int i = 0; i < array.length; i++) {
			if (c == array[i]) return true;
		}
		return false;
	}
	
}