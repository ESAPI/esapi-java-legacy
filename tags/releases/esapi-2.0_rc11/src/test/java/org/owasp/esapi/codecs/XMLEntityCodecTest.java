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
import java.util.Set;

import org.owasp.esapi.util.CollectionsUtil;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

public class XMLEntityCodecTest extends TestCase
{
	private static final char[] EMPTY_CHAR_ARRAY = new char[0];
	private static final String ALPHA_NUMERIC_STR = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	private static final String UNENCODED_STR = ALPHA_NUMERIC_STR + " \t";
	private static final Set<Character> UNENCODED_SET = CollectionsUtil.strToUnmodifiableSet(UNENCODED_STR);
	private XMLEntityCodec codec = null;

	protected void setUp()
	{
		codec = new XMLEntityCodec();
	}

	protected void tearDown()
	{
		codec = null;
	}

	public void testEncodeUnencoded()
	{
		StringBuilder sb = new StringBuilder("AB_YZ");
		String str;

		for(char ch : UNENCODED_SET)
		{
			sb.setCharAt(2,ch);
			str = sb.toString();
			assertEquals(str, codec.encode(EMPTY_CHAR_ARRAY, str));
		}
	}

	public void testEncodeOthers()
	{
		StringBuilder inSb = new StringBuilder("AB_YZ");
		StringBuilder outSb = new StringBuilder("AB&#x");
		String in;
		String expected;
		String result;
		int outSbBaseLen = outSb.length();
		String out;

		for(int c=Character.MIN_VALUE;c<=Character.MAX_VALUE;c++)
		{
			char ch = (char)c;
			if(UNENCODED_SET.contains(ch))
				continue;
			inSb.setCharAt(2,ch);
			in = inSb.toString();
			outSb.append(Integer.toHexString(c));
			outSb.append(";YZ");
			expected = outSb.toString();
			result = codec.encode(EMPTY_CHAR_ARRAY,in);
			assertEquals(expected, result);
			outSb.setLength(outSbBaseLen);
		}
	}

	public void testDecodeUnencoded()
	{
		StringBuilder sb = new StringBuilder("AB_YZ");
		String str;

		for(char ch : UNENCODED_SET)
		{
			sb.setCharAt(2,ch);
			str = sb.toString();
			assertEquals(str, codec.decode(str));
		}
	}

	public void testDecodeHex()
	{
		StringBuilder expectedSb = new StringBuilder("AB_YZ");
		StringBuilder inSb = new StringBuilder("AB&#x");
		String in;
		String expected;
		String result;
		int inSbBaseLen = inSb.length();

		for(int c=Character.MIN_VALUE;c<=Character.MAX_VALUE;c++)
		{
			char ch = (char)c;
			expectedSb.setCharAt(2,ch);
			expected = expectedSb.toString();
			inSb.append(Integer.toHexString(c));
			inSb.append(";YZ");
			in = inSb.toString();
			result = codec.decode(in);
			assertEquals(expected, result);
			inSb.setLength(inSbBaseLen);
		}
	}

	public void testDecodeDec()
	{
		StringBuilder expectedSb = new StringBuilder("AB_YZ");
		StringBuilder inSb = new StringBuilder("AB&#");
		String in;
		String expected;
		String result;
		int inSbBaseLen = inSb.length();

		for(int c=Character.MIN_VALUE;c<=Character.MAX_VALUE;c++)
		{
			char ch = (char)c;
			expectedSb.setCharAt(2,ch);
			expected = expectedSb.toString();
			inSb.append(Integer.toString(c));
			inSb.append(";YZ");
			in = inSb.toString();
			result = codec.decode(in);
			assertEquals(expected, result);
			inSb.setLength(inSbBaseLen);
		}
	}

	public void testDecodeLt()
	{
		String in = "AB&lt;YZ";
		String expected = "AB<YZ";
		String result = codec.decode(in);
		assertEquals(expected,result);
	}

	public void testDecodeGt()
	{
		String in = "AB&gt;YZ";
		String expected = "AB>YZ";
		String result = codec.decode(in);
		assertEquals(expected,result);
	}

	public void testDecodeAmp()
	{
		String in = "AB&amp;YZ";
		String expected = "AB&YZ";
		String result = codec.decode(in);
		assertEquals(expected,result);
	}

	public void testDecodeApos()
	{
		String in = "AB&apos;YZ";
		String expected = "AB'YZ";
		String result = codec.decode(in);
		assertEquals(expected,result);
	}

	public void testDecodeQuot()
	{
		String in = "AB&quot;YZ";
		String expected = "AB\"YZ";
		String result = codec.decode(in);
		assertEquals(expected,result);
	}

	public void testDecodeNamedTail()
	{
		String in = "AB&quot;";
		String expected = "AB\"";
		String result = codec.decode(in);
		assertEquals(expected,result);
	}

	public void testDecodeNamedHead()
	{
		String in = "&quot;YZ";
		String expected = "\"YZ";
		String result = codec.decode(in);
		assertEquals(expected,result);
	}

	public void testDecodeNamedLone()
	{
		String in = "&quot;";
		String expected = "\"";
		String result = codec.decode(in);
		assertEquals(expected,result);
	}

	public void testDecodeNamedNoSemiColonTail()
	{
		String in = "AB&quot";
		String expected = in;
		String result = codec.decode(in);
		assertEquals(expected,result);
	}

	public void testDecodeNamedNoSemiColonHead()
	{
		String in = "&quotYZ";
		String expected = in;
		String result = codec.decode(in);
		assertEquals(expected,result);
	}

	public void testDecodeNamedNoSemiColonLone()
	{
		String in = "&quot";
		String expected = in;
		String result = codec.decode(in);
		assertEquals(expected,result);
	}

	public void testDecodeNamedInvalidTail()
	{
		String in = "AB&pound;";
		String expected = in;
		String result = codec.decode(in);
		assertEquals(expected,result);
	}

	public void testDecodeNamedInvalidHead()
	{
		String in = "&pound;YZ";
		String expected = in;
		String result = codec.decode(in);
		assertEquals(expected,result);
	}

	public void testDecodeNamedInvalidLone()
	{
		String in = "&pound;";
		String expected = in;
		String result = codec.decode(in);
		assertEquals(expected,result);
	}
}
