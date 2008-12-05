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
package org.owasp.esapi.reference;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.StringBufferInputStream;
import java.util.Iterator;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.owasp.esapi.EncryptedProperties;
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

    /**
     * {@inheritDoc}
	 */
	protected void setUp() throws Exception {
		// create a new encrypted properties and put in some data
		DefaultEncryptedProperties instance = new DefaultEncryptedProperties();
		instance.setProperty("one", "two");
		instance.setProperty("two", "three");
		File dir = new File( System.getProperty( "user.home" ), ".esapi");
		dir.mkdir();
		instance.store(new FileOutputStream( new File( dir, "test.properties") ), "testStore");
	}

    /**
     * {@inheritDoc}s
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
	 * Test of keySet method, of class org.owasp.esapi.EncryptedProperties.
	 */
	public void testKeySet() throws Exception {
		System.out.println("keySet");
		DefaultEncryptedProperties instance = new DefaultEncryptedProperties();
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
	 * Test of store method, of class org.owasp.esapi.EncryptedProperties.
	 */
	public void testStore() throws Exception {
		System.out.println("store");
		DefaultEncryptedProperties instance = new DefaultEncryptedProperties();
		instance.setProperty("one", "two");
		instance.setProperty("two", "three");
		File f = new File( System.getProperty( "user.home" ) + "/.esapi", "test.properties" );
		instance.store(new FileOutputStream( f ), "testStore");
	}	
	
	/**
	 * Test of load method, of class org.owasp.esapi.EncryptedProperties.
	 */
	public void testLoad() throws Exception {
		System.out.println("load");
		EncryptedProperties creator = new DefaultEncryptedProperties();
		File f = new File( System.getProperty( "user.home" ) + "/.esapi", "test.properties" );
		creator.setProperty( "one", "two" );
		creator.setProperty( "two", "three" );
        creator.store( new FileOutputStream( f ), "ESAPI test encrypted properties" );

		EncryptedProperties loader = new DefaultEncryptedProperties();
		loader.load( new FileInputStream( f ) );
		assertEquals( "two", loader.getProperty("one" ) );
		assertEquals( "three",  loader.getProperty("two" ) );
	}
	
	/**
	 * Test of store method, of class org.owasp.esapi.EncryptedProperties.
	 */
	public void testMain() throws Exception {
		System.out.println("main");
		File f = new File( System.getProperty( "user.home" ) + "/.esapi", "test.properties" );
		String[] args1 = { f.getAbsolutePath() };
		InputStream orig = System.in;
		String input = "key\r\nvalue\r\n";
		System.setIn( new StringBufferInputStream( input ) );
		DefaultEncryptedProperties.main(args1);
		System.setIn( orig );
		String[] args2 = { "ridiculous.properties" };
		try {
			DefaultEncryptedProperties.main(args2);
			fail();
		} catch( Exception e ) {
			// expected
		}
	}
	
}
