/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2017 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Matt Seil (mseil .at. owasp.org)
 * @created 2017
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
 * @param <T>
 * @since June 1, 2007
 * @see org.owasp.esapi.Encoder
 */
public abstract class AbstractCodec<T> implements Codec<T> {

	/**
	 * Initialize an array to mark which characters are to be encoded. Store the hex
	 * string for that character to save time later. If the character shouldn't be
	 * encoded, then store null.
	 */
	private final String[] hex = new String[256];

	/**
	 * Default constructor
	 */
	public AbstractCodec() {
		for ( char c = 0; c < 0xFF; c++ ) {
			if ( c >= 0x30 && c <= 0x39 || c >= 0x41 && c <= 0x5A || c >= 0x61 && c <= 0x7A ) {
				hex[c] = null;
			} else {
				hex[c] = toHex(c).intern();
			}
		}
	}

	/**
	 * WARNING!!  {@code Character} based Codecs will silently transform code points that are not 
	 * legal UTF code points into garbage data as they will cast them to {@code char}s.  
	 * </br></br>
	 * If you are implementing an {@code Integer} based codec, these will be silently discarded
	 * based on the return from {@code Character.isValidCodePoint( int )}.  This is the preferred
	 * behavior moving forward.  
	 * 
	 * 
	 * {@inheritDoc}
	 */
	@Override
	public String encode(char[] immune, String input) {
		StringBuilder sb = new StringBuilder();
		for(int offset  = 0; offset < input.length(); ) {
			final int point = input.codePointAt(offset);
			if (Character.isBmpCodePoint(point)) {
				//We can then safely cast this to char and maintain legacy behavior.
				sb.append(encodeCharacter(immune, new Character((char) point)));
			} else {
				sb.append(encodeCharacter(immune, point));	
			}
			offset += Character.charCount(point);
		}
		return sb.toString();
	}

	/**
	 * WARNING!!!!  Passing a standard char to this method will resolve to the 
	 * @see #encodeCharacter( char[], int )
	 * method instead of this one!!!  YOU HAVE BEEN WARNED!!!!
	 * 
	 * {@inheritDoc}
	 */
	@Override
	public String encodeCharacter( char[] immune, Character c ) {
		return ""+c;
	}
	
	public String encodeCharacter(char[] immune, char c) {
		throw new IllegalArgumentException("You tried to call encodeCharacter with a char.  Nope.  Use Character instead!");
	}
	
	/* (non-Javadoc)
	 * @see org.owasp.esapi.codecs.Codec#encodeCharacter(char[], int)
	 */
	@Override
	public String encodeCharacter( char[] immune, int codePoint ) {
		String rval = "";
		if(Character.isValidCodePoint(codePoint)){
			rval = new StringBuilder().appendCodePoint(codePoint).toString();
		}
		return rval;
	}



	/* (non-Javadoc)
	 * @see org.owasp.esapi.codecs.Codec#decodeCharacter(org.owasp.esapi.codecs.PushbackString)
	 */
	@Override
	public T decodeCharacter( PushbackSequence<T> input ) {
		return input.next();
	}

	/**
	 * {@inheritDoc}
	 */
	public String getHexForNonAlphanumeric(char c) {
		if(c<0xFF)
			return hex[c];
		return toHex(c);
	}
	
	/**
	 * {@inheritDoc}
	 */
	public String getHexForNonAlphanumeric(int c) {
		if (c<0xFF) {
			return hex[c];
		} else {
			return toHex(c);
		}
	}

	public String toOctal(char c) {
		return Integer.toOctalString(c);
	}

	public String toHex(char c) {
		return Integer.toHexString(c);
	}
	
	public String toHex(int c) {
		return Integer.toHexString(c);
	}

	/**
	 * {@inheritDoc}
	 */
	public boolean containsCharacter( char c, char[] array ) {
		for (char ch : array) {
			if (c == ch) return true;
		}
		return false;
	}

}
