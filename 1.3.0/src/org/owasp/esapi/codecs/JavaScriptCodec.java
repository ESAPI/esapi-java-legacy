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
public class JavaScriptCodec implements Codec {

	public JavaScriptCodec() {
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
		if ( ch == 0x00 ) return "\\0";
		if ( ch == 0x08 ) return "\\b";
		if ( ch == 0x09 ) return "\\t";
		if ( ch == 0x0a ) return "\\n";
		if ( ch == 0x0b ) return "\\v";
		if ( ch == 0x0c ) return "\\f";
		if ( ch == 0x0d ) return "\\r";
		if ( ch == 0x22 ) return "\\\"";
		if ( ch == 0x27 ) return "\\'";
		if ( ch == 0x5c ) return "\\\\";

		// encode up to 256 with \\xHH
        String temp = Integer.toHexString((int)ch);
		if ( ch <= 256 ) {
	        String pad = "00".substring(temp.length() );
	        return "\\x" + pad + temp.toUpperCase();
		}

		// otherwise encode with \\uHHHH
        String pad = "0000".substring(temp.length() );
        return "\\u" + pad + temp.toUpperCase();
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
	 *   \\a - special characters
	 *   \\xHH
	 *   \\uHHHH
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
		
		if ( second.charValue() == '0' ) {
			return new Character( (char)0x00 );
		} else if ( second.charValue() == 'b' ) {
			return new Character( (char)0x08 );
		} else if ( second.charValue() == 't' ) {
			return new Character( (char)0x09 );
		} else if ( second.charValue() == 'n' ) {
			return new Character( (char)0x0a );
		} else if ( second.charValue() == 'v' ) {
			return new Character( (char)0x0b );
		} else if ( second.charValue() == 'f' ) {
			return new Character( (char)0x0c );
		} else if ( second.charValue() == 'r' ) {
			return new Character( (char)0x0d );
		} else if ( second.charValue() == '\"' ) {
			return new Character( (char)0x22 );
		} else if ( second.charValue() == '\'' ) {
			return new Character( (char)0x27 );
		} else if ( second.charValue() == '\\' ) {
			return new Character( (char)0x5c );
			
		// look for \\xXX format
		} else if ( Character.toLowerCase( second.charValue() ) == 'x' ) {
			// Search for exactly 2 hex digits following
			StringBuffer sb = new StringBuffer();
			for ( int i=0; i<2; i++ ) {
				Character c = input.nextHex();
				if ( c != null ) sb.append( c );
			}
			if ( sb.length() == 2 ) {
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
			
		// look for \\uXXXX format
		} else if ( Character.toLowerCase( second.charValue() ) == 'u') {
			// Search for exactly 4 hex digits following
			StringBuffer sb = new StringBuffer();
			for ( int i=0; i<4; i++ ) {
				Character c = input.nextHex();
				if ( c != null ) sb.append( c );
			}
			if ( sb.length() == 4 ) {
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
		}
		
		// not an encoded character
		input.reset();
		return null;
	}

}