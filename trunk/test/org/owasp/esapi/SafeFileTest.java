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
import java.net.URI;
import java.net.URLDecoder;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.owasp.esapi.errors.ValidationException;

/**
 * The Class ExecutorTest.
 * 
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 */
public class SafeFileTest extends TestCase {

	/**
	 * Instantiates a new executor test.
	 * 
	 * @param testName
	 *            the test name
	 */
	public SafeFileTest(String testName) {
		super(testName);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see junit.framework.TestCase#setUp()
	 */
	protected void setUp() throws Exception {
		// none
	}

	/*
	 * (non-Javadoc)
	 * 
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
		TestSuite suite = new TestSuite(SafeFileTest.class);
		return suite;
	}

	String pathWithNullByte = "/temp/file.txt" + (char)0;

	
	public void testJavaFileInjection() {
		System.out.println("testJavaFileInjection");
		for ( int i = 0; i < 512; i++ ) {
			String goodFile = ESAPI.securityConfiguration().getResourceDirectory() + "ESAPI.properties" + (char)i;
			File sf = new File(goodFile);
			if ( sf.exists() ) {
				System.out.println( "  Fail filename.txt" + (char)i + " ("+ i +")" );
			}
			File sf2 = new File(goodFile + "test");
			if ( sf2.exists() ) {
				System.out.println( "  Fail c:\\filename.txt" + (char)i + "test.xml ("+ i +")" );
			}
		}		
	}
	
	public void testJavaDirInjection() {
		System.out.println("testJavaDirInjection");
		for ( int i = 0; i < 512; i++ ) {
			String goodFile = ESAPI.securityConfiguration().getResourceDirectory() + (char)i;
			File sf = new File(goodFile);
			if ( sf.exists() ) {
				System.out.println( "  Fail c:\\dirpath" + (char)i + " ("+ i +")" );
			}
			File sf2 = new File(goodFile + "test");
			if ( sf2.exists() ) {
				System.out.println( "  Fail c:\\dirpath" + (char)i + "test.xml ("+ i +")" );
			}
		}		
	}
	
    static public String toHex(final byte b) {
        final char hexDigit[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
        final char[] array = { hexDigit[(b >> 4) & 0x0f], hexDigit[b & 0x0f] };
        return new String(array);
     }	
	
	public void testNormalPercentEncodedFileInjection() {
		System.out.println("testNormalPercentEncodedFileInjection");
		for ( int i = 0; i < 256; i++ ) {
			String enc1 = ESAPI.securityConfiguration().getResourceDirectory() + "ESAPI.properties" + "%" + toHex( (byte)i );
			String dec1 = URLDecoder.decode(enc1);
			File sf = new File(dec1);
			if ( sf.exists() ) {
				System.out.println( "  Fail: " + enc1 );
			}
		}
	}		

	public void testWeirdPercentEncodedFileInjection() {
		System.out.println("testWeirdPercentEncodedFileInjection");
		for ( int i = 0; i < 256; i++ ) {
			String enc2 = ESAPI.securityConfiguration().getResourceDirectory() + "ESAPI.properties" + "%u00" + toHex( (byte)i );
			String dec2 = URLDecoder.decode(enc2);
			File sf2 = new File(dec2);
			if ( sf2.exists() ) {
				System.out.println( "  Fail: " + enc2 );
			}
		}		
	}
	
	
	/**
	 * Test of executeOSCommand method, of class org.owasp.esapi.Executor
	 * 
	 * @throws Exception
	 *             the exception
	 */
	public void testCreateSafeFile() throws Exception {
		System.out.println("SafeFile");

		// verify file exists
		try{
			String goodFile = ESAPI.securityConfiguration().getResourceDirectory() + "ESAPI.properties";
			File sf = new File(goodFile);
			assertTrue( sf.exists() );
		} catch( Exception e ) {
			fail();
		}

		
		// test percent encoded null byte
		try {
			String pathWithPercentEncodedNullByte = "/temp/file%00.txt";
			new SafeFile( pathWithPercentEncodedNullByte );
			fail();
		} catch (Exception e) {
			// expected
		}

		// test safe file exists
		try {
			String goodFile = ESAPI.securityConfiguration().getResourceDirectory() + "ESAPI.properties";
			File sf = new SafeFile(goodFile);
			assertTrue( sf.exists() );
		} catch( ValidationException e ) {
			// expected
		}
		
		// test null byte
		try {
			new SafeFile( pathWithNullByte );
			fail();
		} catch (ValidationException e) {
			// expected
		}

		// test high byte
		try {
			String pathWithHighByte = "/temp/file.txt" + (char)160;
			new SafeFile( pathWithHighByte );
			fail();
		} catch (ValidationException e) {
			// expected
		}
	}
	
	// test parent constructor
	public void testCreateSafeFileParentConstructor() throws Exception {
		System.out.println("SafeFile parent constructor");
		File parent = new File( "/" );
		try {
			new SafeFile( parent, pathWithNullByte );
			fail();
		} catch (ValidationException e) {
			// expected
		}
	}
	
	
	// test good file with uri constructor
	public void testCreateSafeFileURIConstructor() throws Exception {
		System.out.println("SafeFile URI constructor");
		try {
			String goodFile = ESAPI.securityConfiguration().getResourceDirectory() + "ESAPI.properties";
			File sf = new SafeFile(new URI("file:///" + goodFile ));
			assertTrue( sf.exists() );
		} catch (Exception e) {
			// pass
		}
	
		// test uri constructor with null byte
		try {
			new SafeFile(new URI("file:///test" + (char)0 + ".xml"));
			fail();
		} catch (Exception e) {
			// pass
		}
				
		// test http uri
		try {
			new SafeFile(new URI("http://localserver/test" + (char)0 + ".xml"));
			fail();
		} catch (Exception e) {
			// pass
		}
	}

}
