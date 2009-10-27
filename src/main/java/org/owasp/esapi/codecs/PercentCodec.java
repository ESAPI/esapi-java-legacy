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
 * Implementation of the Codec interface for percent encoding (aka URL encoding).
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 * @see org.owasp.esapi.Encoder
 */
public class PercentCodec extends Codec {

	
	/**
	 * {@inheritDoc}
     *
     * @param immune
     */
	public String encodeCharacter( char[] immune, Character c ) {

		// check for immune characters
		if ( containsCharacter(c, immune ) ) {
			return ""+c;
		}
		
		// check for alphanumeric characters
		String hex = Codec.getHexForNonAlphanumeric(c);
		if ( hex == null ) {
			return ""+c;
		}
		
        if (c < 0x10) {
            hex = '0' + hex;
        }
	    return '%' + hex;
	}
	
	
	
	/**
	 * {@inheritDoc}
	 * 
	 * Formats all are legal both upper/lower case:
	 *   %hh;
	 *   
	 * @param input
	 * 			encoded character using percent characters (such as URL encoding)
	 */
	public Character decodeCharacter( PushbackString input ) {
		input.mark();
		Character first = input.next();
		if ( first == null ) {
			input.reset();
			return null;
		}
		
		// if this is not an encoded character, return null
		if (first != '%' ) {
			input.reset();
			return null;
		}
				
		// Search for exactly 2 hex digits following
		StringBuilder sb = new StringBuilder();
		for ( int i=0; i<2; i++ ) {
			Character c = input.nextHex();
			if ( c != null ) sb.append( c );
		}
		if ( sb.length() == 2 ) {
			try {
				// parse the hex digit and create a character
				int i = Integer.parseInt(sb.toString(), 16);
                if (Character.isValidCodePoint(i)) {
                    return (char) i;
			}
            } catch( NumberFormatException ignored ) { }
		}
		input.reset();
		return null;
	}
	
}