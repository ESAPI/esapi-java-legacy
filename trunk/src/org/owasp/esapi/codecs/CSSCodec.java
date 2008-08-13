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
 * Implementation of the Codec interface for backslash encoding frequently used in JavaScript.
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 * @see org.owasp.esapi.Encoder
 */
public class CSSCodec implements Codec {

	public CSSCodec() {
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
	 * Returns backslash encoded character. This implementation does not support
	 * \\### Latin encoded characters in octal as it is not in ECMAScript v3.
	 */
	public String encodeCharacter( Character c ) {
		char ch = c.charValue();

		// encode up to 256 \x syntax
 		if ( ch <= 256 ) {
	        return "\\" + ch;
		}

		// otherwise encode with \\HHHHHH 
        String temp = Integer.toHexString((int)ch);
        return "\\" + temp.toUpperCase() + " ";
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
	 *   \\x - special characters
	 *   \\HHHH
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
		if ( second == null ) {
			input.reset();
			return null;
		}
		
		// look for \HHH format
		if ( input.isHexDigit( second ) ) {
			// Search for up to 6 hex digits following until a space
			StringBuffer sb = new StringBuffer();
			sb.append( second );
			for ( int i=0; i<5; i++ ) {
				Character c = input.next();
				if ( c == null || c.charValue() == 0x20 ) break;
				if ( input.isHexDigit(c) ) {
					sb.append( c );
				} else {
					input.pushback( c );
					break;
				}
			}
			try {
				// parse the hex digit and create a character
				int i = Integer.parseInt(sb.toString(), 16);
				// TODO: in Java 1.5 you can test whether this is a valid code point
				// with Character.isValidCodePoint() et al.
				return new Character( (char)i );
			} catch( NumberFormatException e ) {
				// throw an exception for malformed entity?
				// just continue which will reset and return null
			}
		}

		return second;
	}

}