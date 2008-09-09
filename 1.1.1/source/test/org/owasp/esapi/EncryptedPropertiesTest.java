/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * http://www.owasp.org/esapi.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the LGPL. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2007
 */
package org.owasp.esapi;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.StringBufferInputStream;
import java.util.Iterator;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.owasp.esapi.errors.EncryptionException;

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

	/* (non-Javadoc)
	 * @see junit.framework.TestCase#setUp()
	 */
	protected void setUp() throws Exception {
		// none
	}

	/* (non-Javadoc)
	 * @see junit.framework.TestCase#tearDown()
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
		EncryptedProperties instance = new EncryptedProperties();
		String name = "name";
		String value = "value";
		instance.setProperty(name, value);
		String result = instance.getProperty(name);
		assertEquals(value, result);
		try {
			instance.getProperty("ridiculous");
			fail();
		} catch( Exception e ) {
			// expected
		}
	}

	/**
	 * Test of setProperty method, of class org.owasp.esapi.EncryptedProperties.
	 * 
	 * @throws EncryptionException
	 *             the encryption exception
	 */
	public void testSetProperty() throws EncryptionException {
		System.out.println("setProperty");
		EncryptedProperties instance = new EncryptedProperties();
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
	 * Test of keySet method, of class org.owasp.esapi.EncryptedProperties.
	 */
	public void testKeySet() throws Exception {
		System.out.println("keySet");
		EncryptedProperties instance = new EncryptedProperties();
		instance.setProperty("one", "two");
		instance.setProperty("two", "three");
		Iterator i = instance.keySet().iterator();
		assertEquals( "two", (String)i.next() );
		assertEquals( "one", (String)i.next() );
		try {
			i.next();
			fail();
		} catch( Exception e ) {
			// expected
		}
	}
	
	/**
	 * Test of load method, of class org.owasp.esapi.EncryptedProperties.
	 */
	public void testLoad() throws Exception {
		System.out.println("load");
		EncryptedProperties instance = new EncryptedProperties();
		File f = new File( ((SecurityConfiguration)ESAPI.securityConfiguration()).getResourceDirectory(), "test.properties" );
		instance.load( new FileInputStream( f ) );
		assertEquals( "two", instance.getProperty("one" ) );
		assertEquals( "three",  instance.getProperty("two" ) );
	}
	
	/**
	 * Test of store method, of class org.owasp.esapi.EncryptedProperties.
	 */
	public void testStore() throws Exception {
		System.out.println("store");
		EncryptedProperties instance = new EncryptedProperties();
		instance.setProperty("one", "two");
		instance.setProperty("two", "three");
		File f = new File( ((SecurityConfiguration)ESAPI.securityConfiguration()).getResourceDirectory(), "test.properties" );
		instance.store(new FileOutputStream( f ), "testStore");
	}

	/**
	 * Test of store method, of class org.owasp.esapi.EncryptedProperties.
	 */
	public void testMain() throws Exception {
		System.out.println("main");
		File f = new File( ((SecurityConfiguration)ESAPI.securityConfiguration()).getResourceDirectory(), "test.properties" );
		String[] args1 = { f.getAbsolutePath() };
		InputStream orig = System.in;
		String input = "key\r\nvalue\r\n";
		System.setIn( new StringBufferInputStream( input ) );
		EncryptedProperties.main(args1);
		System.setIn( orig );
		String[] args2 = { "ridiculous.properties" };
		try {
			EncryptedProperties.main(args2);
			fail();
		} catch( Exception e ) {
			// expected
		}
	}
	
}
