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

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.Arrays;
import java.util.HashMap;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Logger;
import org.owasp.esapi.codecs.Base64;
import org.owasp.esapi.errors.EncodingException;
import org.owasp.esapi.errors.IntrusionException;

import sun.text.Normalizer;

/**
 * Reference implementation of the Encoder interface. This implementation takes
 * 
 * 
 * 
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 * @see org.owasp.esapi.Encoder
 */
public class PercentCodec extends Codec {

	public PercentCodec() {
	}

	public String encode( String input ) {
		return null;
	}
	
	public String decode( String input ) {
		StringBuffer sb = new StringBuffer();
		PushbackString pbs = new PushbackString( input );
		while ( pbs.hasNext() ) {
			pbs.mark();
			Character c = getDecodedCharacter( pbs );
			if ( c != null ) {
				sb.append( c );
			} else {
				pbs.reset();
				sb.append( pbs.next() );
			}
		}
		return sb.toString();
	}
	
	/**
	 * Returns the decoded version of the character starting at index, or
	 * null if no decoding is possible.
	 * 
	 * Formats all are legal both with and without semi-colon, upper/lower case:
	 *   &#dddd;
	 *   &#xhhhh;
	 *   &name;
	 */
	public Character getDecodedCharacter( PushbackString input ) {
		Character first = input.next();
		if ( first == null ) return null;
		
		// if this is not an encoded character, return null
		if ( first.charValue() != '%' ) return null;
				
		// Search for exactly 2 hex digits following %
		StringBuffer sb = new StringBuffer();
		if ( input.hasNext() ) {
			Character c = input.next();
			if ( "0123456789ABCDEFabcdef".indexOf( c.charValue() ) != -1 ) {
				sb.append( c );
			} else return null;
		} else return null;
		if ( input.hasNext() ) {
			Character c = input.next();
			if ( "0123456789ABCDEFabcdef".indexOf( c.charValue() ) != -1 ) {
				sb.append( c );
			} else return null;
		} else return null;
		
		// parse the hex digit and create a character
		try {
			int i = Integer.parseInt(sb.toString(), 16);
			// FIXME: in Java 1.5 you can test whether this is a valid code point
			// with Character.isValidCodePoint() et al.
			return new Character( (char)i );
		} catch( NumberFormatException e ) {
			// throw an exception for malformed entity?
			return null;
		}
	}
	
		
	public static void main( String[] args ) {
		PercentCodec codec = new PercentCodec();
		String test = "%2526 %3cscript%3e";
		System.out.println( "Original: " + test );
		System.out.println( "Decoded: " + codec.decode( test ) );
	}
}