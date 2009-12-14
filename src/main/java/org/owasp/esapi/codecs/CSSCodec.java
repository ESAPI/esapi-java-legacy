/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP) Enterprise Security API
 * (ESAPI) project. For details, please see <a
 * href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 * 
 * Copyright (c) 2007 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the LICENSE
 * before you use, modify, and/or redistribute this software.
 * 
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2007
 */
package org.owasp.esapi.codecs;

import java.util.Set;

import org.owasp.esapi.util.CollectionsUtil;
import org.owasp.esapi.util.PrimWrap;

/**
 * Implementation of the Codec interface for backslash encoding used in CSS.
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 * @see org.owasp.esapi.Encoder
 */
public class CSSCodec implements Codec
{
	private static final String ALPHA_NUMERIC_STR = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	private static final String UNENCODED_STR = ALPHA_NUMERIC_STR + " \t";
	private static final Set/*<Character>*/ UNENCODED_SET = CollectionsUtil.strToUnmodifiableSet(UNENCODED_STR);

	/**
	 * Public Constructor for CSSCodec
	 */
	public CSSCodec() {
	}

	/**
	 * {@inheritDoc}
	 * 
	 * This method encodes a String to safely be used in CSS.
	 * 
	 */
	public String encode(String input) {
		StringBuffer sb = new StringBuffer();
		for (int i = 0; i < input.length(); i++) {
			char c = input.charAt(i);
			sb.append(encodeCharacter(PrimWrap.wrapChar(c)));
		}
		return sb.toString();
	}

	/**
	 * Encodes a character for use in CSS.
	 * @param c The character to encode
	 * @return c encoded for use in CSS.
	 */
	public String encodeCharacter(Character c) {
		char ch = c.charValue();

		if(UNENCODED_SET.contains(c))
			return c.toString();

		// CSS 2.1 section 4.1.3: "It is undefined in CSS 2.1
		// what happens if a style sheet does contain a character
		// with Unicode codepoint zero."
		if(ch == 0)
			throw new IllegalArgumentException("Chracter value zero is not valid in CSS");

		// otherwise encode with \\HHHHHH
		String temp = Integer.toHexString((int) ch);
		return "\\" + temp.toUpperCase() + " ";
	}

	/**
	 * {@inheritDoc}
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
	 * {@inheritDoc}
	 * Returns the decoded version of the character starting at index, or null if no decoding is
	 * possible.
	 * 
	 * Formats all are legal both upper/lower case: \\x - special characters \\HHHH
	 */
	public Character decodeCharacter(PushbackString input) {
		input.mark();
		Character first = input.next();
		if (first == null) {
			input.reset();
			return null;
		}

		// if this is not an encoded character, return null
		if (first.charValue() != '\\') {
			input.reset();
			return null;
		}

		Character second = input.next();
		if (second == null) {
			input.reset();
			return null;
		}


		// look for \HHH format
		if (input.isHexDigit(second)) {
			// Search for up to 6 hex digits following until a space
			StringBuffer sb = new StringBuffer();
			sb.append(second);
			for (int i = 0; i < 5; i++) {
				Character c = input.next();
				if (c == null || c.charValue() == 0x20)
					break;
				if (input.isHexDigit(c)) {
					sb.append(c);
				} else {
					input.pushback(c);
					break;
				}
			}
			try {
				// parse the hex digit and create a character
				int i = Integer.parseInt(sb.toString(), 16);
				// TODO: in Java 1.5 you can test whether this is a valid code point
				// with Character.isValidCodePoint() et al.
				return new Character((char) i);
			} catch (NumberFormatException e) {
				// throw an exception for malformed entity?
				// just continue which will reset and return null
			}
		}

		return second;
	}

}
