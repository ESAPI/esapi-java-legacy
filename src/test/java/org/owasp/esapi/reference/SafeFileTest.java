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
import java.util.Iterator;
import java.util.Set;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.owasp.esapi.SafeFile;
import org.owasp.esapi.errors.ValidationException;
import org.owasp.esapi.util.FileTestUtils;
import org.owasp.esapi.util.CollectionsUtil;

/**
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 */
public class SafeFileTest extends TestCase
{
	private static final Class CLASS = SafeFileTest.class;
	private static final String CLASS_NAME = CLASS.getName();
	/** Name of the file in the temporary directory */
	private static final String TEST_FILE_NAME = "test.file";
	private static final Set GOOD_FILE_CHARS = CollectionsUtil.strToUnmodifiableSet("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-");
	private static final Set BAD_FILE_CHARS = CollectionsUtil.strToUnmodifiableSet("\u0000" + (File.separatorChar == '/' ? '\\' : '/') + "*|<>?:" /*+ "~!@#$%^&(){}[],`;"*/);

	private File testDir = null;
	private File testFile = null;

	String pathWithNullByte = "/temp/file.txt" + (char)0;

	/**
	 * {@inheritDoc}
	 */
	protected void setUp() throws Exception
	{
		// create a file to test with
		testDir = FileTestUtils.createTmpDirectory(CLASS_NAME).getCanonicalFile();
		testFile = new File(testDir, TEST_FILE_NAME);
		testFile.createNewFile();
		testFile = testFile.getCanonicalFile();
	}

	/**
	 * {@inheritDoc}
	 */
	protected void tearDown() throws Exception
	{
		FileTestUtils.deleteRecursively(testDir);
	}

	public static Test suite() {
		TestSuite suite = new TestSuite(SafeFileTest.class);
		return suite;
	}

	public void testEscapeCharactersInFilename() {
		System.out.println("testEscapeCharactersInFilenameInjection");
		File tf = testFile;
		if ( tf.exists() ) {
			System.out.println( "File is there: " + tf );
		}

		File sf = new File(testDir, "test^.file" );
		if ( sf.exists() ) {
			System.out.println( "  Injection allowed "+ sf.getAbsolutePath() );
		} else {
			System.out.println( "  Injection didn't work "+ sf.getAbsolutePath() );
		}
	}

	public void testEscapeCharacterInDirectoryInjection() {
		System.out.println("testEscapeCharacterInDirectoryInjection");
		File sf = new File(testDir, "test\\^.^.\\file");
		if ( sf.exists() ) {
			System.out.println( "  Injection allowed "+ sf.getAbsolutePath() );
		} else {
			System.out.println( "  Injection didn't work "+ sf.getAbsolutePath() );
		}
	}

	public void testJavaFileInjectionGood() throws ValidationException
	{
		for(Iterator i=GOOD_FILE_CHARS.iterator();i.hasNext();)
		{
			String ch = i.next().toString();	// avoids generic issues in 1.4&1.5
			File sf = new SafeFile(testDir, TEST_FILE_NAME + ch);
			assertFalse("File " + sf.getPath() + " should not exist.", sf.exists());
			sf = new SafeFile(testDir, TEST_FILE_NAME + ch + "test");
			assertFalse("File " + sf.getPath() + " should not exist.", sf.exists());
		}		
	}

	public void testJavaFileInjectionBad()
	{
		for(Iterator i=BAD_FILE_CHARS.iterator();i.hasNext();)
		{
			String ch = i.next().toString();	// avoids generic issues in 1.4&1.5
			try
			{
				File sf = new SafeFile(testDir, TEST_FILE_NAME + ch);
				fail("Able to create SafeFile " + sf.getPath());
			}
			catch(ValidationException expected)
			{
			}
			try
			{
				File sf = new SafeFile(testDir, TEST_FILE_NAME + ch  + "test");
				fail("Able to create SafeFile " + sf.getPath());
			}
			catch(ValidationException expected)
			{
			}
		}		
	}

	public void testMultipleJavaFileInjectionGood() throws ValidationException
	{
		for(Iterator i=GOOD_FILE_CHARS.iterator();i.hasNext();)
		{
			String ch = i.next().toString();	// avoids generic issues in 1.4&1.5
			ch = ch + ch + ch;
			File sf = new SafeFile(testDir, TEST_FILE_NAME + ch);
			assertFalse("File " + sf.getPath() + " should not exist.", sf.exists());
			sf = new SafeFile(testDir, TEST_FILE_NAME + ch + "test");
			assertFalse("File " + sf.getPath() + " should not exist.", sf.exists());
		}		
	}

	public void testMultipleJavaFileInjectionBad()
	{
		for(Iterator i=BAD_FILE_CHARS.iterator();i.hasNext();)
		{
			String ch = i.next().toString();	// avoids generic issues in 1.4&1.5
			ch = ch + ch + ch;
			try
			{
				File sf = new SafeFile(testDir, TEST_FILE_NAME + ch);
				fail("Able to create SafeFile " + sf.getPath());
			}
			catch(ValidationException expected)
			{
			}
			try
			{
				File sf = new SafeFile(testDir, TEST_FILE_NAME + ch  + "test");
				fail("Able to create SafeFile " + sf.getPath());
			}
			catch(ValidationException expected)
			{
			}
		}		
	}

	public void testAlternateDataStream() {
		try
		{
			File sf = new SafeFile(testDir, TEST_FILE_NAME + ":secret.txt");
			fail("Able to construct SafeFile for alternate data stream: " + sf.getPath());
		}
		catch(ValidationException expected)
		{
		}
	}

	static public String toHex(final byte b) {
		final char hexDigit[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
		final char[] array = { hexDigit[(b >> 4) & 0x0f], hexDigit[b & 0x0f] };
		return new String(array);
	}	

	public void testCreatePath() throws Exception
	{
		SafeFile sf = new SafeFile(testFile.getPath());
		assertTrue(sf.exists());
	}

	public void testCreateParentPathName() throws Exception
	{
		SafeFile sf = new SafeFile(testDir, testFile.getName());
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
			SafeFile sf = new SafeFile(testDir + File.separator + "file%00.txt");
			fail("no exception thrown for file name with percent encoded null");
		}
		catch(ValidationException expected)
		{
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

}
