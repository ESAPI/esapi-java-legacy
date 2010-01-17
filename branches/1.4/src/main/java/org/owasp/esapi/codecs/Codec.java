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
public interface Codec {

	/**
	 * Encode a String with a Codec
	 * 
	 * @param input
	 * 		the String to encode
	 * @return the encoded String
	 */
	String encode( String input ); 
	
	/**
	 * Encode a Character with a Codec
	 * 
	 * @param c
	 * 		the Character to encode
	 * @return
	 * 		the encoded Character
	 */
	String encodeCharacter( Character c );
	
	/**
	 * Decode a String that was encoded using the encode method in this Class
	 * 
	 * @param input
	 * 		the String to decode
	 * @return
	 *		the decoded String
	 */
	String decode( String input );
	

	/**
	 * Returns the decoded version of the next character from the input string and advances the
	 * current character in the PushbackString.  If the current character is not encoded, this 
	 * method MUST reset the PushbackString.
	 * 
	 * @param input	the Character to decode
	 * 
	 * @return the decoded Character
	 */
	public Character decodeCharacter( PushbackString input );
	
}