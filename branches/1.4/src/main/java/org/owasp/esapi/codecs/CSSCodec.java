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
	private static final Character REPLACEMENT = PrimWrap.wrapChar('\ufffd');

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
	 * 
	 * Returns the decoded version of the character starting at index,
	 * or null if no decoding is possible.
	 */
	public Character decodeCharacter(PushbackString input)
	{
		input.mark();
		Character first = input.next();
		if (first == null || first.charValue() != '\\')
		{
			input.reset();
			return null;
		}

		Character second = input.next();
		if (second == null) {
			input.reset();
			return null;
		}

		/* From css 2.1 spec:
		 * http://www.w3.org/TR/CSS21/syndata.html#characters
		 *
		 * First, inside a string, a backslash followed by a
		 * newline is ignored (i.e., the string is deemed not
		 * to contain either the backslash or the newline).
		 *
		 * Second, it cancels the meaning of special CSS
		 * characters. Except within CSS comments, any character
		 * (except a hexadecimal digit, linefeed, carriage return,
		 * or form feed) can be escaped with a backslash to
		 * remove its special meaning. For example, "\"" is a string
		 * consisting of one double quote. Style sheet
		 * preprocessors must not remove these backslashes
		 * from a style sheet since that would change the style
		 * sheet's meaning.
		 *
		 * Third, backslash escapes allow authors to refer to
		 * characters they cannot easily put in a document. In
		 * this case, the backslash is followed by at most six
		 * hexadecimal digits (0..9A..F), which stand for the ISO
		 * 10646 ([ISO10646]) character with that number, which
		 * must not be zero. (It is undefined in CSS 2.1 what
		 * happens if a style sheet does contain a character with
		 * Unicode codepoint zero.) If a character in the range
		 * [0-9a-fA-F] follows the hexadecimal number, the end
		 * of the number needs to be made clear. There are two
		 * ways to do that:
		 *
		 *	1. with a space (or other white space character):
		 *	"\26 B" ("&B"). In this case, user agents should
		 *	treat a "CR/LF" pair (U+000D/U+000A) as a single
		 *	white space character.
		 *
		 *	2. by providing exactly 6 hexadecimal digits:
		 *	"\000026B" ("&B")
		 *
		 * In fact, these two methods may be combined. Only one
		 * white space character is ignored after a hexadecimal
		 * escape. Note that this means that a "real" space
		 * after the escape sequence must itself either be
		 * escaped or doubled.
		 *
		 * If the number is outside the range allowed by Unicode
		 * (e.g., "\110000" is above the maximum 10FFFF allowed in
		 * current Unicode), the UA may replace the escape with
		 * the "replacement character" (U+FFFD). If the character
		 * is to be displayed, the UA should show a visible
		 * symbol, such as a "missing character" glyph (cf. 15.2,
		 * point 5).
		 */

		switch(second.charValue())
		{	// special whitespace cases. I assume they mean
			// for all of these to qualify as a "new
			// line." Otherwise there is no specification
			// of what to do for \f
			case '\r':
				if(input.peek('\n'))
					input.next();
				// fall through
			case '\n':
			case '\f':
				// bs follwed by new line replaced by nothing
			case '\u0000':	// skip NUL for now too
				return decodeCharacter(input);
		}

		if (!PushbackString.isHexDigit(second))
		{	// non hex digit
			return second;
		}

		// Search for up to 6 hex digits following until a space
		StringBuffer sb = new StringBuffer();
		sb.append(second);
		for (int i = 0; i < 5; i++)
		{
			Character c = input.next();
			if(c == null || Character.isWhitespace(c.charValue()))
				break;
			if(PushbackString.isHexDigit(c))
				sb.append(c);
			else
			{
				input.pushback(c);
				break;
			}
		}
		try
		{
			// parse the hex digit and create a character
			int i = Integer.parseInt(sb.toString(), 16);
	
			if (i <= 0x10ffff)
				return PrimWrap.wrapChar((char)i);
			return REPLACEMENT;
		}
		catch (NumberFormatException e)
		{
			IllegalStateException ise = new IllegalStateException("Received a NumberFormateException parsing a string verified to be hex");
			ise.initCause(e);
			throw ise;
        	}
	}
}