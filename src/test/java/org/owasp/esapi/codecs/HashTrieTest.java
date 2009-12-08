package org.owasp.esapi.codecs;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map.Entry;
import java.util.Set;
import java.util.ArrayList;
import java.util.Collections;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.owasp.esapi.util.PrimWrap;

public class HashTrieTest extends TestCase
{
	private static final Class/*<HashTrieTest>*/ CLASS = HashTrieTest.class;

	public HashTrieTest(String testName)
	{
		super(testName);
	}

	private static boolean objBool(Object o)
	{
		if(o == null)
			throw new NullPointerException("null object passed");
		if(!(o instanceof Boolean))
			throw new IllegalArgumentException("Object passed was not Boolean but " + o.getClass());
		return ((Boolean)o).booleanValue();
	}

	private void assertTrue(Object o)
	{
		assertTrue(objBool(o));
	}

	private void assertFalse(Object o)
	{
		assertFalse(objBool(o));
	}

	public void testSingleInsertLookup()
	{
		HashTrie/*<Boolean>*/ trie = new HashTrie/*<Boolean>*/();

		trie.put("true", Boolean.TRUE);
		assertEquals(Boolean.TRUE, trie.get("true"));
		assertNull(trie.get("not there"));
		assertNull(trie.get("tru"));
		assertNull(trie.get("trueX"));
		assertEquals("true".length(), trie.getMaxKeyLength());
	}

	public void testEmpty()
	{
		HashTrie/*<Boolean>*/ trie = new HashTrie/*<Boolean>*/();
		assertNull(trie.get("true"));
		assertNull(trie.get("false"));
		assertNull(trie.get(""));
		assertTrue(trie.getMaxKeyLength()<0);
	}

	public void testTwoInsertLookup()
	{
		HashTrie/*<Boolean>*/ trie = new HashTrie/*<Boolean>*/();

		trie.put("true", Boolean.TRUE);
		trie.put("false", Boolean.FALSE);
		assertEquals(Boolean.TRUE, trie.get("true"));
		assertEquals(Boolean.FALSE, trie.get("false"));
		assertEquals("false".length(),trie.getMaxKeyLength());
	}

	public void testMatchingPrefix()
	{
		HashTrie/*<Boolean>*/ trie = new HashTrie/*<Boolean>*/();

		trie.put("pretrue", Boolean.TRUE);
		trie.put("prefalse", Boolean.FALSE);
		assertEquals(Boolean.TRUE, trie.get("pretrue"));
		assertEquals(Boolean.FALSE, trie.get("prefalse"));
	}

	public void testPrefixIsValidKey()
	{
		HashTrie/*<Boolean>*/ trie = new HashTrie/*<Boolean>*/();

		trie.put("pre", Boolean.TRUE);
		trie.put("prefalse", Boolean.FALSE);
		assertEquals(Boolean.TRUE, trie.get("pre"));
		assertEquals(Boolean.FALSE, trie.get("prefalse"));
	}

	public void testDuplicateAdd()
	{
		HashTrie/*<Boolean>*/ trie = new HashTrie/*<Boolean>*/();

		assertNull(trie.put("dup", Boolean.TRUE));
		assertTrue(trie.put("dup", Boolean.FALSE));
		assertFalse(trie.get("dup"));
	}

	public void testTwoInsertLongestLookup()
	{
		HashTrie/*<Boolean>*/ trie = new HashTrie/*<Boolean>*/();
		Entry/*<CharSequence,Boolean>*/ entry;

		trie.put("true", Boolean.TRUE);
		trie.put("true idea", Boolean.TRUE);
		trie.put("false", Boolean.FALSE);

		assertNotNull((entry = trie.getLongestMatch("true")));
		assertEquals("true", entry.getKey());
		assertTrue(entry.getValue());

		assertNotNull((entry = trie.getLongestMatch("false")));
		assertEquals("false", entry.getKey());
		assertFalse(entry.getValue());

		assertNotNull((entry = trie.getLongestMatch("truer")));
		assertEquals("true", entry.getKey());
		assertTrue(entry.getValue());

		assertNotNull((entry = trie.getLongestMatch("true to form")));
		assertEquals("true", entry.getKey());
		assertTrue(entry.getValue());

		assertNotNull((entry = trie.getLongestMatch("false result")));
		assertEquals("false", entry.getKey());
		assertFalse(entry.getValue());

		assertNull(trie.getLongestMatch("not there"));
		assertNull(trie.getLongestMatch("tru"));
		assertNull(trie.getLongestMatch("fals"));
	}

	public void testContainsKey()
	{
		HashTrie/*<Boolean>*/ trie = new HashTrie/*<Boolean>*/();

		trie.put("true", Boolean.TRUE);
		trie.put("false", Boolean.FALSE);
		assertTrue(trie.containsKey("true"));
		assertTrue(trie.containsKey("false"));
		assertFalse(trie.containsKey("not there"));
	}

	public void testContainsValue()
	{
		HashTrie/*<Integer>*/ trie = new HashTrie/*<Integer>*/();

		trie.put("one", PrimWrap.wrapInt(1));
		trie.put("two", PrimWrap.wrapInt(2));
		assertTrue(trie.containsValue(PrimWrap.wrapInt(1)));
		assertTrue(trie.containsValue(PrimWrap.wrapInt(2)));
		assertFalse(trie.containsValue(PrimWrap.wrapInt(3)));
	}

	public void testKeySet()
	{
		HashTrie/*<Boolean>*/ trie = new HashTrie/*<Boolean>*/();
		HashSet/*<CharSequence>*/ expected = new HashSet/*<CharSequence>*/(2);

		expected.add("true");
		expected.add("false");
		trie.put("true", Boolean.TRUE);
		trie.put("false", Boolean.FALSE);
		assertEquals(expected,trie.keySet());
	}

	public void testValues()
	{
		HashTrie/*<Boolean>*/ trie = new HashTrie/*<Boolean>*/();
		ArrayList/*<Boolean>*/ actual;
		ArrayList/*<Boolean>*/ expected = new ArrayList/*<Boolean>*/(2);

		expected.add(Boolean.TRUE);
		expected.add(Boolean.FALSE);
		trie.put("true", Boolean.TRUE);
		trie.put("false", Boolean.FALSE);
		actual = new ArrayList/*<Boolean>*/(trie.values());
		Collections.sort(actual);
		Collections.sort(expected);
		assertEquals(expected,actual);
	}

	public void testEntrySet()
	{
		HashTrie/*<Boolean>*/ trie = new HashTrie/*<Boolean>*/();
		HashMap/*<CharSequence,Boolean>*/ equivMap = new HashMap/*<CharSequence,Boolean>*/(2);

		equivMap.put("true",Boolean.TRUE);
		equivMap.put("false",Boolean.FALSE);
		trie.put("true", Boolean.TRUE);
		trie.put("false", Boolean.FALSE);
		assertEquals(equivMap.entrySet(),trie.entrySet());
	}

	public void testEquals()
	{
		HashTrie/*<Boolean>*/ trie = new HashTrie/*<Boolean>*/();
		HashMap/*<CharSequence,Boolean>*/ equivMap = new HashMap/*<CharSequence,Boolean>*/(2);

		equivMap.put("true",Boolean.TRUE);
		equivMap.put("false",Boolean.FALSE);
		trie.put("true", Boolean.TRUE);
		trie.put("false", Boolean.FALSE);
		assertTrue(trie.equals(equivMap));
	}

	public void testHashCode()
	{
		HashTrie/*<Boolean>*/ trie = new HashTrie/*<Boolean>*/();
		HashMap/*<CharSequence,Boolean>*/ equivMap = new HashMap/*<CharSequence,Boolean>*/(2);

		equivMap.put("true",Boolean.TRUE);
		equivMap.put("false",Boolean.FALSE);
		trie.put("true", Boolean.TRUE);
		trie.put("false", Boolean.FALSE);
		assertEquals(equivMap.hashCode(),trie.hashCode());
	}

	/**
	 * Create a test suite with just this test.
	 * @return A test swuite with just this test.
	 */
	public static Test suite()
	{
		TestSuite suite = new TestSuite(CLASS);
		return suite;
	}
}
