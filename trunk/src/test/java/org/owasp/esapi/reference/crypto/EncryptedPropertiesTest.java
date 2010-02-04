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
package org.owasp.esapi.reference.crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.StringBufferInputStream;
import java.util.Iterator;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.errors.EncryptionException;
import org.owasp.esapi.reference.crypto.DefaultEncryptedProperties;

/**
 * The Class EncryptedPropertiesTest.
 * 
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 */
public class EncryptedPropertiesTest extends TestCase {

	/**
	 * Instantiates a new encrypted properties test.
	 * 
	 * @param testName
	 *            the test name
	 */
	public EncryptedPropertiesTest(String testName) {
		super(testName);
	}

	/**
	 * {@inheritDoc}
	 */
	protected void setUp() throws Exception {
		// none
	}

	/**
	 * {@inheritDoc}
	 */
	protected void tearDown() throws Exception {
		// none
	}

	/**
	 * Suite.
	 * 
	 * @return the test
	 */
	public static Test suite() {
		TestSuite suite = new TestSuite(EncryptedPropertiesTest.class);

		return suite;
	}

	/**
	 * Test of getProperty method, of class org.owasp.esapi.EncryptedProperties.
	 * 
	 * @throws EncryptionException
	 *             the encryption exception
	 */
	public void testGetProperty() throws EncryptionException {
		System.out.println("getProperty");
		DefaultEncryptedProperties instance = new DefaultEncryptedProperties();
		String name = "name";
		String value = "value";
		instance.setProperty(name, value);
		String result = instance.getProperty(name);
		assertEquals(value, result);
		assertNull(instance.getProperty("ridiculous"));
	}

	/**
	 * Test of setProperty method, of class org.owasp.esapi.EncryptedProperties.
	 * 
	 * @throws EncryptionException
	 *             the encryption exception
	 */
	public void testSetProperty() throws EncryptionException {
		System.out.println("setProperty");
		DefaultEncryptedProperties instance = new DefaultEncryptedProperties();
		String name = "name";
		String value = "value";
		instance.setProperty(name, value);
		String result = instance.getProperty(name);
		assertEquals(value, result);
		try {
			instance.setProperty(null, null);
			fail();
		} catch( Exception e ) {
			// expected
		}
	}

	/**
	 * Test the behavior when the requested key does not exist.
	 */
	public void testNonExistantKeyValue() throws Exception
	{
		DefaultEncryptedProperties instance = new DefaultEncryptedProperties();
		assertNull(instance.getProperty("not.there"));
	}

	/**
	 * Test of keySet method, of class org.owasp.esapi.EncryptedProperties.
	 */
	public void testKeySet() throws Exception
	{
		boolean sawTwo = false;
		boolean sawOne = false;

		System.out.println("keySet");
		DefaultEncryptedProperties instance = new DefaultEncryptedProperties();
		instance.setProperty("one", "two");
		instance.setProperty("two", "three");
		Iterator i = instance.keySet().iterator();
		while(i.hasNext())
		{
			String key = (String)i.next();

			assertNotNull("key returned from keySet() iterator was null", key);
			if(key.equals("one"))
				if(sawOne)
					fail("Key one seen more than once.");
				else
					sawOne = true;
			else if(key.equals("two"))
				if(sawTwo)
					fail("Key two seen more than once.");
				else
					sawTwo = true;
			else
				fail("Unset key " + key + " returned from keySet().iterator()");
		}
		assertTrue("Key one was never seen", sawOne);
		assertTrue("Key two was never seen", sawTwo);
	}

	/**
	 * Test storing and loading of encrypted properties.
	 */
	public void testStoreLoad() throws Exception
	{
		DefaultEncryptedProperties toStore = new DefaultEncryptedProperties();
		DefaultEncryptedProperties toLoad = new DefaultEncryptedProperties();
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		ByteArrayInputStream bais;
		boolean sawOne = false;
		boolean sawTwo = false;

		toStore = new DefaultEncryptedProperties();
		toStore.setProperty("one", "two");
		toStore.setProperty("two", "three");
		toStore.store(baos, "testStore");

		bais = new ByteArrayInputStream(baos.toByteArray());
		toLoad.load(bais);

		for(Iterator i=toLoad.keySet().iterator();i.hasNext();)
		{
			String key = (String)i.next();

			assertNotNull("key returned from keySet() iterator was null", key);
			if(key.equals("one"))
				if(sawOne)
					fail("Key one seen more than once.");
				else
				{
					sawOne = true;
					assertEquals("Key one's value was not two", "two", toLoad.getProperty("one"));
				}
			else if(key.equals("two"))
				if(sawTwo)
					fail("Key two seen more than once.");
				else
				{
					sawTwo = true;
					assertEquals("Key two's value was not three", "three", toLoad.getProperty("two"));
				}
			else
				fail("Unset key " + key + " returned from keySet().iterator()");
		}
		assertTrue("Key one was never seen", sawOne);
		assertTrue("Key two was never seen", sawTwo);
	}

}
