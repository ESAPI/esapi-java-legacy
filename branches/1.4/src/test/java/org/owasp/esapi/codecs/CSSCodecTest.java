/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2009 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 */
package org.owasp.esapi.codecs;

import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import org.owasp.esapi.util.CollectionsUtil;
import org.owasp.esapi.util.PrimWrap;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

public class CSSCodecTest extends TestCase
{
	private static final char[] EMPTY_CHAR_ARRAY = new char[0];
	private static final Character LESS_THAN = PrimWrap.wrapChar('<');
	private static final String ALPHA_NUMERIC_STR = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	private static final String HEX_DIGIT_STR = "abcdefABCDEF0123456789";
	private static final String NO_BS_SELF_STR = HEX_DIGIT_STR + "\n\r\f";
	private static final String UNENCODED_STR = ALPHA_NUMERIC_STR + " \t";
	private static final Set/*<Character>*/ UNENCODED_SET = CollectionsUtil.strToUnmodifiableSet(UNENCODED_STR);
	private CSSCodec codec = null;

	protected void setUp()
	{
		codec = new CSSCodec();
	}

	protected void tearDown()
	{
		codec = null;
	}

	public void testEncodeLessThan()
	{
		assertEquals( "\\3C ", codec.encode(/*EMPTY_CHAR_ARRAY,*/ "<") );
	}

	public void testEncodeLessThanChar()
	{
		assertEquals( "\\3C ", codec.encodeCharacter(/*EMPTY_CHAR_ARRAY,*/ LESS_THAN) );
	}

	/**
	 * Verify a list of characters is not encoded. For the moment
	 * this is just alpha numerics space and tab.
	 */
	public void testEncodeUnencodedChars()
	{
		int len = UNENCODED_STR.length();

		for(int i=0;i<len;i++)
		{
			char ch = UNENCODED_STR.charAt(i);
			String result = codec.encodeCharacter(PrimWrap.wrapChar(ch));
			String expected = Character.toString(ch);

			assertEquals("Character " + ch + " was not left unencoded", expected, result);
		}
	}

	/**
	 * Test encoding of a zero character code. 
	 * According to the CSS 2.1 recomendation section 4.1.3: "It is
	 * undefined in CSS 2.1 what happens if a style sheet does
	 * contain a character with Unicode codepoint zero."
	 */
	public void testEncodeZero()
	{
		try
		{
			codec.encodeCharacter(PrimWrap.wrapChar((char)0));
			fail("Encoding of a zero character code should throw an exception.");
		}
		catch(Exception e)
		{
			// correct
		}
	}

	/**
	 * Test that certain characters aren't escaped without hex.
	 * The CSS 2.1 recommendation section 4.1.3 states "Except
	 * within CSS comments, any character (except a hexadecimal digit,
	 * linefeed, carriage return, or form feed) can be escaped with
	 * a backslash to remove its special meaning." This test verifies
	 * that these characters are not encoded in this manner.
	 */
	public void testNotBackSlashCharOnHexDigit()
	{
		int len = NO_BS_SELF_STR.length();

		for(int i=0;i<len;i++)
		{
			char ch = NO_BS_SELF_STR.charAt(i);
			String result = codec.encodeCharacter(PrimWrap.wrapChar(ch));
			String bad = "\\" + ch;

			assertFalse("codec encoded " + ch + " as " + result + " which is incorrect as the value after the back slash will be treated as a hexadecimal value and not just an escaping of the given character", bad.equals(result));
		}
	}

	public void testEncodeChar0x100()
	{
		char in = 0x100;
		String inStr = Character.toString(in);
		String expected = "\\100 ";
		String result;

        	result = codec.encodeCharacter(/*EMPTY_CHAR_ARRAY,*/ PrimWrap.wrapChar(in));
		// this should be escaped
        	assertFalse(inStr.equals(result));
        	assertEquals(expected,result);
	}

	public void testEncodeStr0x100()
	{
		char in = 0x100;
		String inStr = Character.toString(in);
		String expected = "\\100 ";
		String result;

        	result = codec.encode(/*EMPTY_CHAR_ARRAY,*/ inStr);
		// this should be escaped
        	assertFalse(inStr.equals(result));
        	assertEquals(expected,result);
	}

	public void testDecodeLessThan()
	{
		assertEquals( "<", codec.decode("\\<") );
	}

	public void testDecodeLessThanCharBackSlashHex()
	{
		assertEquals( LESS_THAN, codec.decodeCharacter(new PushbackString("\\3c") ));
	}
}
