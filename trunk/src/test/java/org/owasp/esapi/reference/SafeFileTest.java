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
import java.net.URI;
import java.net.URLDecoder;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.owasp.esapi.SafeFile;
import org.owasp.esapi.errors.ValidationException;

/**
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 */
public class SafeFileTest extends TestCase
{
	private static final Class<SafeFileTest> CLASS = SafeFileTest.class;
	private static final String CLASS_NAME = CLASS.getName();

	private File testFile = null;
	private File testParent = null;

	String pathWithNullByte = "/temp/file.txt" + (char)0;

	protected void setUp() throws Exception
	{
		// create a file to test with
		testFile = File.createTempFile(CLASS_NAME, null);
		testFile = testFile.getCanonicalFile();
		testParent = testFile.getParentFile();
	}

	protected void tearDown() throws Exception
	{
		if(testFile != null && testFile.exists() && !testFile.delete())
		{
			System.err.println("Unable to delete temporary file " + testFile + ". Deletion of file at JVM exit will be attempted.");
			testFile.deleteOnExit();
		}
	}

	public static Test suite() {
		TestSuite suite = new TestSuite(SafeFileTest.class);
		return suite;
	}

	public void testEscapeCharactersInFilename() {
		
		System.out.println("testEscapeCharactersInFilenameInjection");
		File tf = new File( System.getProperty("user.home","test.file" ));
		if ( tf.exists() ) {
			System.out.println( "File is there: " + tf );
		}

		File sf = new File( System.getProperty("user.home","test^.file" ));
		if ( sf.exists() ) {
			System.out.println( "  Injection allowed "+ sf.getAbsolutePath() );
		} else {
			System.out.println( "  Injection didn't work "+ sf.getAbsolutePath() );
		}
	}

	public void testEscapeCharacterInDirectoryInjection() {
		System.out.println("testEscapeCharacterInDirectoryInjection");
		File sf = new File( System.getProperty("user.home","test\\^.^.\\file" ));
		if ( sf.exists() ) {
			System.out.println( "  Injection allowed "+ sf.getAbsolutePath() );
		} else {
			System.out.println( "  Injection didn't work "+ sf.getAbsolutePath() );
		}
	}

	public void testJavaFileInjection() {
		System.out.println("testJavaFileInjection");
		for ( int i = 0; i < 512; i++ ) {
			File sf = new File( System.getProperty("user.home","test.file"+(char)i ));
			if ( sf.exists() ) {
				System.out.println( "  Fail filename.txt" + (char)i + " ("+ i +")" );
			}
			File sf2 = new File( System.getProperty("user.home","test.file"+ (char)i + "test" ));
			if ( sf2.exists() ) {
				System.out.println( "  Fail c:\\filename.txt" + (char)i + "test.xml ("+ i +")" );
			}
		}		
	}


	public void testMultipleJavaFileInjection() {
		System.out.println("testMultipleJavaFileInjection");
		for ( int i = 0; i < 512; i++ ) {
			File sf = new File( System.getProperty("user.home","test.file" + (char)i + (char)i + (char)i ) );
			if ( sf.exists() ) {
				System.out.println( "  Fail filename.txt"  + (char)i  + (char)i + (char)i + " ("+ i +") 3x" );
			}
			File sf2 = new File( System.getProperty("user.home","test.file" + (char)i + (char)i + (char)i + "test") );
			if ( sf2.exists() ) {
				System.out.println( "  Fail c:\\filename.txt"  + (char)i + (char)i + (char)i + "test.xml ("+ i +") 3x" );
			}
		}       
	}

	public void testAlternateDataStream() {
		System.out.println("testAlternateDataStream");
		File sf = new File( System.getProperty("user.home","test.file:secret.txt" ) );
		if ( sf.exists() ) {
			// this actually works on Windows, so it's not really a failure, just sort of interesting
			System.out.println( "  Fail:" + sf );
		}
	}

	public void testJavaDirInjection() {
		System.out.println("testJavaDirInjection");
		for ( int i = 0; i < 512; i++ ) {
			String goodFile = System.getProperty("user.home") + (char)i;
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

	public void testNormalPercentEncodedFileInjection() throws Exception {
		System.out.println("testNormalPercentEncodedFileInjection");
		for ( int i = 0; i < 256; i++ ) {
			String enc1 = System.getProperty("user.home") + "%" + toHex( (byte)i );
			String dec1 = URLDecoder.decode(enc1, "UTF-8");
			File sf = new File(dec1);
			if ( sf.exists() ) {
				System.out.println( "  Fail: " + enc1 );
			}
		}
	}		

	public void testWeirdPercentEncodedFileInjection() throws Exception {
		System.out.println("testWeirdPercentEncodedFileInjection");
		for ( int i = 0; i < 256; i++ ) {
			String enc2 = System.getProperty("user.home") + "%u00" + toHex( (byte)i );
			try {
				String dec2 = URLDecoder.decode(enc2, "UTF-8");
				File sf2 = new File(dec2);
				if ( sf2.exists() ) {
					System.out.println( "  Fail: " + enc2 );
				}
			} catch (Exception e ) {
				// expected
			}
		}		
	}

	public void testCreatePath() throws Exception
	{
		SafeFile sf = new SafeFile(testFile.getPath());
		assertTrue(sf.exists());
	}

	public void testCreateParentPathName() throws Exception
	{
		SafeFile sf = new SafeFile(testFile.getParent(), testFile.getName());
		assertTrue(sf.exists());
	}

	public void testCreateParentFileName() throws Exception
	{
		SafeFile sf = new SafeFile(testFile.getParentFile(), testFile.getName());
		assertTrue(sf.exists());
	}

	public void testCreateURI() throws Exception
	{
		SafeFile sf = new SafeFile(testFile.toURI());
		assertTrue(sf.exists());
	}

	public void testCreateFileNamePercentNull()
	{
		try
		{
			SafeFile sf = new SafeFile(testFile.getParent() + File.separator + "file%00.txt");
			fail("no exception thrown for file name with percent encoded null");
		}
		catch(ValidationException e)
		{
			// expected
		}
	}

	public void testCreateFileNameQuestion()
	{
		try
		{
			SafeFile sf = new SafeFile(testFile.getParent() + File.separator + "file?.txt");
			fail("no exception thrown for file name with question mark in it");
		}
		catch(ValidationException e)
		{
			// expected
		}
	}

	public void testCreateFileNameNull()
	{
		try
		{
			SafeFile sf = new SafeFile(testFile.getParent() + File.separator + "file" + ((char)0) + ".txt");
			fail("no exception thrown for file name with null in it");
		}
		catch(ValidationException e)
		{
			// expected
		}
	}

	public void testCreateFileHighByte()
	{
		try
		{
			SafeFile sf = new SafeFile(testFile.getParent() + File.separator + "file" + ((char)160) + ".txt");
			fail("no exception thrown for file name with high byte in it");
		}
		catch(ValidationException e)
		{
			// expected
		}
	}

	public void testCreateParentPercentNull()
	{
		try
		{
			SafeFile sf = new SafeFile(testFile.getParent() + File.separator + "file%00.txt");
			fail("no exception thrown for file name with percent encoded null");
		}
		catch(ValidationException e)
		{
			// expected
		}
	}

	// test parent constructor
	/**
	 *
	 * @throws java.lang.Exception
	 */
	public void testCreateSafeFileParentConstructor() throws Exception {
		System.out.println("SafeFile parent constructor");
		try {
			new SafeFile( new File( "/" ), pathWithNullByte );
			fail();
		} catch (ValidationException e) {
			// expected
		}

		try {
			new SafeFile( new File("/%00"), "test.txt" );
			fail();
		} catch (ValidationException e) {
			// expected
		}

		try {
			new SafeFile( new File("/\0"), "test.txt" );
			fail();
		} catch (ValidationException e) {
			// expected
		}

		try {
			new SafeFile( new File("/|test"), "test.txt" );
			fail();
		} catch (ValidationException e) {
			// expected
		}

	}


	// test good file with uri constructor
	/**
	 *
	 * @throws java.lang.Exception
	 */
	public void testCreateSafeFileURIConstructor() throws Exception {
		System.out.println("SafeFile URI constructor");
		// create a file to test with

		File testFile = null;

		try {
			String uri = testFile.toURI().toASCIIString();
			File sf = new SafeFile(new URI(uri));
			assertTrue(sf.exists());
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
