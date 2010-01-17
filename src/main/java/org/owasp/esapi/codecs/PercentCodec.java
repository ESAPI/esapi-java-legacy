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

import java.io.UnsupportedEncodingException;
import java.util.Set;

import org.owasp.esapi.util.CollectionsUtil;

/**
 * Implementation of the Codec interface for percent encoding (aka URL encoding).
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 * @see org.owasp.esapi.Encoder
 */
public class PercentCodec implements Codec
{
	private static final char[] EMPTY_CHAR_ARRAY = new char[0];
	private static final String ALPHA_NUMERIC_STR = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	private static final String RFC3986_RESERVED_STR = ":/?#[]@!$&'()*+,;=";
	private static final String RFC3986_NON_ALPHANUMERIC_UNRESERVED_STR = "-._~";
		// rfc3986 2.3: For consistency, percent-encoded octets
		// in the ranges of ALPHA (%41-%5A and %61-%7A), DIGIT
		// (%30-%39), hyphen (%2D), period (%2E), underscore
		// (%5F), or tilde (%7E) should not be created by URI
		// producers
	private static final boolean ENCODED_NON_ALPHA_NUMERIC_UNRESERVED = true;
	private static final String UNENCODED_STR = ALPHA_NUMERIC_STR +
		(ENCODED_NON_ALPHA_NUMERIC_UNRESERVED ? "" : RFC3986_NON_ALPHANUMERIC_UNRESERVED_STR);
	private static final Set UNENCODED_SET = CollectionsUtil.strToUnmodifiableSet(UNENCODED_STR);

	public PercentCodec() {
	}

	/**
	 * Convinence method to encode a string into UTF-8. This
	 * wraps the {@link UnsupportedEncodingException} that
	 * {@link String.getBytes(String)} throws in a
	 * {@link IllegalStateException} as UTF-8 support is required
	 * by the Java spec and should never throw this exception.
	 * @param str the string to encode
	 * @return str encoded in UTF-8 as bytes.
	 * @throws IllegalStateException with info from a {@link
	 *	UnsupportedEncodingException} if
	 *	{@link String.getBytes(String)} throws it.
	 */
	private static byte[] toUtf8Bytes(String str)
	{
		try
		{
			return str.getBytes("UTF-8");
		}
		catch(UnsupportedEncodingException e)
		{
			throw new IllegalStateException("The Java spec requires UTF-8 support. UnsupportedEncodingException message: " + e.getMessage());
		}
	}

	/**
	 * Append the two upper case hex characters for a byte.
	 * @param sb The string buffer to append to.
	 * @param b The byte to hexify
	 * @returns sb with the hex characters appended.
	 */
	// rfc3986 2.1: For consistency, URI producers 
	// should use uppercase hexadecimal digits for all percent-
	// encodings.
	private static StringBuffer appendTwoUpperHex(StringBuffer sb, int b)
	{
		if(b < Byte.MIN_VALUE || b > Byte.MAX_VALUE)
			throw new IllegalArgumentException("b is not a byte (was " + b + ')');
		b &= 0xFF;
		if(b<0x10)
			sb.append('0');
		return sb.append(Integer.toHexString(b).toUpperCase());
	}

	/**
	 * Encode a character for URLs and append it.
	 * @param sb buffer to append to
	 * @param c character to encode
	 * @return sb after appending the encoded character.
	 */
	protected StringBuffer appendEncodedCharacter(StringBuffer sb, Character c)
	{
		char ch = c.charValue();
		byte[] bytes;

		if(UNENCODED_SET.contains(c))
			return sb.append(ch);

		bytes = toUtf8Bytes(String.valueOf(ch));
		for(int i=0;i<bytes.length;i++)
		{
			byte b = bytes[i];
			appendTwoUpperHex(sb.append('%'), b);
		}
		return sb;
	}

	/**
	 * Encode a character for URLs
	 * @param c character to encode
	 * @return the encoded string representing c
	 */
	public String encodeCharacter(Character c)
	{
		if(UNENCODED_SET.contains(c))
			return String.valueOf(c.charValue());
			
		return appendEncodedCharacter(new StringBuffer(10),c).toString();
	}

	/**
	 * {@inheritDoc}
	 */
	public String encode(String input)
	{
		StringBuffer sb = new StringBuffer();
		int inLen = input.length();

		for(int i=0;i<inLen;i++)
			appendEncodedCharacter(sb,new Character(input.charAt(i)));
		return sb.toString();
	}
	
	/**
	 * {@inheritDoc}
	 * 
	 * Decode string encoded with percent characters
	 * 
	 * @param input
	 * 			encoded string using percent characters (such as URL encoding)
	 */
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
		if ( first.charValue() != '%' ) {
			input.reset();
			return null;
		}
				
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
		input.reset();
		return null;
	}

}
