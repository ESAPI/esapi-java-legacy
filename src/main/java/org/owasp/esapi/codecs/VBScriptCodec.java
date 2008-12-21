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

import org.owasp.esapi.reference.DefaultEncoder;


/**
 * Implementation of the Codec interface for 'quote' encoding from VBScript.
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 * @see org.owasp.esapi.Encoder
 */
public class VBScriptCodec extends Codec {

	/**
	 * Encode a String so that it can be safely used in a specific context.
	 * 
     * @param immune
     * @param input
	 * 		the String to encode
	 * @return the encoded String
	 */
    public String encode(char[] immune, String input) {
		StringBuffer sb = new StringBuffer();
		boolean encoding = false;
		boolean inquotes = false;
		for ( int i=0; i<input.length(); i++ ) {
			char c = input.charAt(i);
			
			// handle normal characters and surround them with quotes
			if (containsCharacter(c, DefaultEncoder.CHAR_ALPHANUMERICS) || containsCharacter(c, immune)) {
				if ( encoding && i > 0 ) sb.append( "&" );
				if ( !inquotes && i > 0 ) sb.append( "\"" );
				sb.append( c );
				inquotes = true;
				encoding = false;
				
			// handle characters that need encoding
			} else {
				if ( inquotes && i < input.length() ) sb.append( "\"" );
				if ( i > 0 ) sb.append( "&" );
				sb.append( encodeCharacter( immune, new Character( c ) ) );
				inquotes = false;
				encoding = true;
			}
		}
		return sb.toString();
    }


	/**
	 * Returns quote-encoded character
     *
     * @param immune
     */
	public String encodeCharacter( char[] immune, Character c ) {
		char ch = c.charValue();
		
		// check for immune characters
		if ( containsCharacter( ch, immune ) ) {
			return ""+ch;
		}
		
		// check for alphanumeric characters
		String hex = Codec.getHexForNonAlphanumeric( c );
		if ( hex == null ) {
			return ""+ch;
		}
		
        return "chrw(" + (int)c.charValue() + ")";
	}
	
	
	
	/**
	 * Returns the decoded version of the character starting at index, or
	 * null if no decoding is possible.
	 * 
	 * Formats all are legal both upper/lower case:
	 *   "x - all special characters
	 *   " + chr(x) + "  - not supported yet
	 */
	public Character decodeCharacter( PushbackString input ) {
		input.mark();
		Character first = input.next();
		if ( first == null ) {
			input.reset();
			return null;
		}
		
		// if this is not an encoded character, return null
		if ( first.charValue() != '\"' ) {
			input.reset();
			return null;
		}

		Character second = input.next();
		return second;
	}

}