package org.owasp.esapi.codecs;

import java.util.Arrays;

import org.owasp.esapi.util.PrimWrap;

/**
 * Abstract implementation to ease back porting from 2.0. In 2.0 Codec
 * became a abstract class instead of a interface. Most of this code is
 * snipped from there.
 */
public abstract class AbstractCodec implements Codec
{
	private static final char[] EMPTY_CHAR_ARRAY = new char[0];

	/**
	 * Check for the existance of a character in an array.
	 * @param array Array of charachters to search
	 * @param c The character to search for.
	 * @return true if c was found. false otherwise.
	 */
	private static final boolean contains(char[] array, char c)
	{
		if(array == null)
			return false;
		for(int i=0;i<array.length;i++)
			if(array[i]==c)
				return true;
		return false;
	}

	/**
	 * Check for the existance of a character in an array.
	 * @param c The character to search for.
	 * @param array Array of charachters to search
	 * @return true if c was found. false otherwise.
	 */
	public static final boolean containsCharacter(Character c, char[] array)
	{
		return contains(array,c.charValue());
	}

	/**
	 * Check for the existance of a character in an array.
	 * @param array Array of charachters that have previously been sorted.
	 * @param c The character to search for.
	 * @return true if c was found. false otherwise.
	 */
	private static final boolean sortedContains(char[] array, char c)
	{
		if(array == null)
			return false;
		return (Arrays.binarySearch(array, c) >= 0);
	}

	/**
	 * Creates a copy of an array and sorts it.
	 * @param array Array of characters to copy and sort.
	 * @return A copy of array which has been sorted.
	 */
	private static final char[] copyAndSort(char[] array)
	{
		char[] ret;

		if(array == null || array.length <= 0)
			return EMPTY_CHAR_ARRAY;
		ret = new char[array.length];
		for(int i=0;i<array.length;i++)
			ret[i] = array[i];
		Arrays.sort(ret);
		return ret;
	}

	/**
	 * Decode a String that was encoded using the encode method in
	 * this Class
	 * @param input the String to decode
	 * @return the decoded String
	 */
	public String decode(String input)
	{
		StringBuffer sb = new StringBuffer();
		PushbackString pbs = new PushbackString(input);
		while (pbs.hasNext())
		{
			Character c = decodeCharacter(pbs);
			if (c != null)
			{
				sb.append(c);
			}
			else
			{
				sb.append(pbs.next());
			}
		}
		return sb.toString();
	}

	/**
	 * Encode a Character with a Codec. This implementation delegates
	 * to {@link #encodecharacter(char[],character)}
	 * with a empty immune array. either this or
	 * {@link #encodecharacter(char[],character)} must be overridden
	 * by subclasses.
	 * @param c the Character to encode
	 * @return the encoded Character
	 */
	public String encodeCharacter( Character c )
	{
		return encodeCharacter(EMPTY_CHAR_ARRAY, c);
	}

	/**
	 * Encode a character with immunity. This implementation
	 * checks for a immune character and then delegates to
	 * {@link #encodeCharacter(Character)}. Either this or
	 * {@link #encodeCharacter(Character)} must be overridden by
	 * subclasses.
	 * @param immune characters not to encode
	 * @return String representation of the encoded character.
	 */
	public String encodeCharacter(char[] immune, Character c)
	{
		if(contains(immune, c.charValue()))
			return c.toString();
		return encodeCharacter(c);
	}

	/**
	 * Encode a String so that it can be safely used in a specific context.
	 * @param immune characters not to encode
	 * @param input the String to encode
	 * @return the encoded String
	 */
	public String encode(char[] immune, String input)
	{
		StringBuffer sb = new StringBuffer();

		for (int i=0; i<input.length();i++)
			sb.append(encodeCharacter(immune, PrimWrap.wrapChar(input.charAt(i))));
		return sb.toString();
	}

	/**
	 * Encode a String without immunity. This implementation simply
	 * delegates to {@link #encode(char[], String)} with a empty
	 * immunity array.
	 * @param input the String to encode
	 * @return the encoded String
	 */
	public String encode(String input)
	{
		return encode(EMPTY_CHAR_ARRAY, input);
	}
}
