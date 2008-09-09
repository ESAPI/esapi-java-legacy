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
 * Implementation of the Codec interface for '\' encoding from Unix command shell.
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 * @see org.owasp.esapi.Encoder
 */
public class UnixCodec implements Codec {

	public UnixCodec() {
	}

	public String encode( String input ) {
		StringBuffer sb = new StringBuffer();
		for ( int i=0; i<input.length(); i++ ) {
			char c = input.charAt(i);
			sb.append( encodeCharacter( new Character( c ) ) );
		}
		return sb.toString();
	}

	/**
	 * Returns backslash-encoded character
	 */
	public String encodeCharacter( Character c ) {
        return "\\" + c;
	}
	
	public String decode( String input ) {
		StringBuffer sb = new StringBuffer();
		PushbackString pbs = new PushbackString( input );
		while ( pbs.hasNext() ) {
			Character c = decodeCharacter( pbs );
			if ( c != null ) {
				sb.append( c );
			} else {
				sb.append( pbs.next() );
			}
		}
		return sb.toString();
	}
	
	
	/**
	 * Returns the decoded version of the character starting at index, or
	 * null if no decoding is possible.
	 * 
	 * Formats all are legal both upper/lower case:
	 *   \x - all special characters
	 */
	public Character decodeCharacter( PushbackString input ) {
		input.mark();
		Character first = input.next();
		if ( first == null ) {
			input.reset();
			return null;
		}
		
		// if this is not an encoded character, return null
		if ( first.charValue() != '\\' ) {
			input.reset();
			return null;
		}

		Character second = input.next();
		return second;
	}

}