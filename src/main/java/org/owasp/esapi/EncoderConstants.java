package org.owasp.esapi;

import java.util.Set;

import org.owasp.esapi.util.CollectionsUtil;

/**
 * Common character classes used for input validation, output encoding, verifying password strength
 * CSRF token generation, generating salts, etc
 * @author Neil Matatall (neil.matatall .at. gmail.com)
 * @see User
 */
public class EncoderConstants {
	/**
	 * _.!@$*+-?
	 */
	public final static char[] CHAR_PASSWORD_SPECIALS = { '_', '.', '!', '@', '$', '*', '=', '-', '?' };
	public final static Set<Character> PASSWORD_SPECIALS;
	static {
		PASSWORD_SPECIALS = CollectionsUtil.arrayToSet(CHAR_PASSWORD_SPECIALS);
	}
	
	/**
	 * a-b
	 */
	public final static char[] CHAR_LOWERS = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
	public final static Set<Character> LOWERS;
	static {
		LOWERS = CollectionsUtil.arrayToSet(CHAR_PASSWORD_SPECIALS);
	}
	
	/**
	 * A-Z
	 */
	public final static char[] CHAR_UPPERS = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' };
	public final static Set<Character> UPPERS;
	static {
		UPPERS = CollectionsUtil.arrayToSet(CHAR_UPPERS);
	}
	/**
	 * 0-9
	 */
	public final static char[] CHAR_DIGITS = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' };
	public final static Set<Character> DIGITS;
	static {
		DIGITS = CollectionsUtil.arrayToSet(CHAR_DIGITS);
	}
	
	/**
	 * .-_!@$^*=~!+?
	 */
	public final static char[] CHAR_SPECIALS = { '.', '-', '_', '!', '@', '$', '^', '*', '=', '~', '|', '+', '?' };
	public final static Set<Character> SPECIALS;
	static {
		SPECIALS = CollectionsUtil.arrayToSet(CHAR_SPECIALS);
	}
	
	/**
	 * CHAR_LOWERS union CHAR_UPPERS
	 */
	public final static char[] CHAR_LETTERS = StringUtilities.union(CHAR_LOWERS, CHAR_UPPERS);
	public final static Set<Character> LETTERS;
	static {
		LETTERS = CollectionsUtil.arrayToSet(CHAR_LETTERS);
	}
	
	/**
	 * CHAR_LETTERS union CHAR_DIGITS
	 */
	public final static char[] CHAR_ALPHANUMERICS = StringUtilities.union(CHAR_LETTERS, CHAR_DIGITS);
	public final static Set<Character> ALPHANUMERICS;
	static {
		ALPHANUMERICS = CollectionsUtil.arrayToSet(CHAR_ALPHANUMERICS);
	}
	
	/**
	 * Password character set, is alphanumerics (without l, i, I, o, O, and 0)
	 * selected specials like + (bad for URL encoding, | is like i and 1,
	 * etc...)
	 */
	public final static char[] CHAR_PASSWORD_LOWERS = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'j', 'k', 'm', 'n', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
	public final static Set<Character> PASSWORD_LOWERS;
	static {
		PASSWORD_LOWERS = CollectionsUtil.arrayToSet(CHAR_ALPHANUMERICS);
	}
	
	/**
	 * 
	 */
	public final static char[] CHAR_PASSWORD_UPPERS = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' };
	public final static Set<Character> PASSWORD_UPPERS;
	static {
		PASSWORD_UPPERS = CollectionsUtil.arrayToSet(CHAR_PASSWORD_UPPERS);
	}
	
	/**
	 * 2-9
	 */
	public final static char[] CHAR_PASSWORD_DIGITS = { '2', '3', '4', '5', '6', '7', '8', '9' };
	public final static Set<Character> PASSWORD_DIGITS;
	static {
		PASSWORD_DIGITS = CollectionsUtil.arrayToSet(CHAR_PASSWORD_DIGITS);
	}
	
	/**
	 * CHAR_PASSWORD_LOWERS union CHAR_PASSWORD_UPPERS
	 */
	public final static char[] CHAR_PASSWORD_LETTERS = StringUtilities.union( CHAR_PASSWORD_LOWERS, CHAR_PASSWORD_UPPERS );
	public final static Set<Character> PASSWORD_LETTERS;
	static {
		PASSWORD_LETTERS = CollectionsUtil.arrayToSet(CHAR_PASSWORD_LETTERS);
	}

	private EncoderConstants() {
		// prevent instantiation
	}
}
