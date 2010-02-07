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
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Executor;
import org.owasp.esapi.SecurityConfiguration;
import org.owasp.esapi.SecurityConfigurationWrapper;
import org.owasp.esapi.codecs.Codec;
import org.owasp.esapi.codecs.WindowsCodec;
import org.owasp.esapi.codecs.UnixCodec;
import org.owasp.esapi.util.FileTestUtils;


/**
 * The Class ExecutorTest.
 * 
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 */
public class ExecutorTest extends TestCase
{
	private static final Class CLASS = ExecutorTest.class;
	private static final boolean IS_WINDOWS = (System.getProperty("os.name").indexOf("Windows") >= 0);
	private static final String JAVA_CMD_NAME;
	private static final File JAVA_CMD;
	private static final File JAVA_HOME;
	private static final File JAVA_HOME_BIN;
	private static final File TMP_DIR;
	private SecurityConfiguration origConfig;
	private Codec codec;
	private Executor instance;

	static
	{
		try
		{
			JAVA_CMD = FileTestUtils.getJavaExe();
			JAVA_CMD_NAME = JAVA_CMD.getName();
			JAVA_HOME = FileTestUtils.getJavaHome();
			JAVA_HOME_BIN = FileTestUtils.getJavaBin();
			TMP_DIR = FileTestUtils.getJavaIoTmpDir();
		}
		catch(IOException e)
		{
			throw new IllegalStateException("IOException setting static Files that should exist.", e);
		}
	}

	/**
	 * Config wrapper to temporarly set the allowedExecutables and
	 * workingDirectory.
	 */
	private static class Conf extends SecurityConfigurationWrapper
	{
		private List allowedExes;
		private File workingDir;

		/**
		 * Create wrapper with the specified allowed execs and
		 * workingDir.
		 * @param orig The configuration to wrap.
		 * @param allowedExec The executables to be allowed
		 * @param workingDir The working directory for execution
		 */
		Conf(SecurityConfiguration orig, List allowedExes, File workingDir)
		{
			super(orig);
			this.allowedExes = allowedExes;
			this.workingDir = workingDir;
		}

		/**
		 * Override real one with our temporary one.
		 * @return Temporary allowed executables.
		 */
		public List getAllowedExecutables()
		{
			return allowedExes;
		}

		/**
		 * Override real one with our temporary one.
		 * @return Temporary working directory.
		 */
		public File getWorkingDirectory()
		{
			return workingDir;
		}
	}

	/**
	 * Instantiates a new executor test.
	 * 
	 * @param testName
	 *            the test name
	 */
	public ExecutorTest(String testName) {
		super(testName);
	}

	/**
	 * {@inheritDoc}
	 */
	protected void setUp() throws Exception {
		// save configuration as tests change it
		origConfig = ESAPI.securityConfiguration();
		ESAPI.setSecurityConfiguration(
				new Conf(
					ESAPI.securityConfiguration(),
					Collections.singletonList(JAVA_CMD.getPath()),
					TMP_DIR
					)
				);
		instance = ESAPI.executor();
		if (IS_WINDOWS)
			codec = new WindowsCodec();
		else
			codec = new UnixCodec();
	}

	/**
	 * {@inheritDoc}
	 */
	protected void tearDown() throws Exception {
		// restore configuration as tests change it
		ESAPI.setSecurityConfiguration(origConfig);
	}

	/**
	 * Suite.
	 * 
	 * @return the test
	 */
	public static Test suite() {
		TestSuite suite = new TestSuite(ExecutorTest.class);
		return suite;
	}

	/**
	 * Test of executeOSCommand method, of class org.owasp.esapi.Executor
	 * 
	 * @throws Exception
	 *             the exception
	 */
	public void testExecuteWindowsSystemCommand() throws Exception {
		System.out.println("executeWindowsSystemCommand");

		if (!IS_WINDOWS)
		{
			System.out.println("testExecuteWindowsSystemCommand - on non-Windows platform, exiting");
			return;	// Not windows, not going to execute this path
		}

		Codec codec = new WindowsCodec();
		System.out.println("executeSystemCommand");
		Executor instance = ESAPI.executor();
		File executable = new File( "C:\\Windows\\System32\\cmd.exe" );
		File working = new File("C:\\");
		List params = new ArrayList();
		try {
			params.add("/C");
			params.add("dir");
			String result = instance.executeSystemCommand(executable, new ArrayList(params), working, codec);
			System.out.println( "RESULT: " + result );
			assertTrue(result.length() > 0);
		} catch (Exception e) {
			fail(e.getMessage());
		}
		try {
			File exec2 = new File( executable.getPath() + ";inject.exe" );
			String result = instance.executeSystemCommand(exec2, new ArrayList(params), working, codec);
			System.out.println( "RESULT: " + result );
			fail();
		} catch (Exception e) {
			// expected
		}
		try {
			File exec2 = new File( executable.getPath() + "\\..\\cmd.exe" );
			String result = instance.executeSystemCommand(exec2, new ArrayList(params), working, codec);
			System.out.println( "RESULT: " + result );
			fail();
		} catch (Exception e) {
			// expected
		}
		try {
			File workdir = new File( "ridiculous" );
			String result = instance.executeSystemCommand(executable, new ArrayList(params), workdir, codec);
			System.out.println( "RESULT: " + result );
			fail();
		} catch (Exception e) {
			// expected
		}
		try {
			params.add("&dir");
			String result = instance.executeSystemCommand(executable, new ArrayList(params), working, codec);
			System.out.println( "RESULT: " + result );
		} catch (Exception e) {
			fail();
		}

		try {
			params.set( params.size()-1, "c:\\autoexec.bat" );
			String result = instance.executeSystemCommand(executable, new ArrayList(params), working, codec);
			System.out.println( "RESULT: " + result );
		} catch (Exception e) {
			fail();
		}

		try {
			params.set( params.size()-1, "c:\\autoexec.bat c:\\config.sys" );
			String result = instance.executeSystemCommand(executable, new ArrayList(params), working, codec);
			System.out.println( "RESULT: " + result );
		} catch (Exception e) {
			fail();
		}
	}

	/**
	 * Test of executeOSCommand method, of class org.owasp.esapi.Executor
	 * 
	 * @throws Exception
	 *             the exception
	 */
	public void testExecuteUnixSystemCommand() throws Exception {
		System.out.println("executeUnixSystemCommand");
		File workingDir = new File("/tmp");

		if (IS_WINDOWS)
		{
			System.out.println("executeUnixSystemCommand - on Windows platform, exiting");
			return;
		}

		// FIXME: need more test cases to use this codec
		Codec codec = new UnixCodec();

		// make sure we have what /bin/sh is pointing at in the allowed exes for the test
		// and a usable working dir
		File binSh = new File("/bin/sh").getCanonicalFile();
		ESAPI.setSecurityConfiguration(
				new Conf(
					ESAPI.securityConfiguration(),
					Collections.singletonList(binSh.getPath()),
					workingDir
					)
				);

		Executor instance = ESAPI.executor();
		File executable = binSh;
		List params = new ArrayList();
		try {
			params.add("-c");
			params.add("ls");
			params.add("/");
			String result = instance.executeSystemCommand(executable, new ArrayList(params), workingDir, codec);
			System.out.println( "RESULT: " + result );
			assertTrue(result.length() > 0);
		} catch (Exception e) {
			fail(e.getMessage());
		}
		try {
			File exec2 = new File( executable.getPath() + ";./inject" );
			String result = instance.executeSystemCommand(exec2, new ArrayList(params), workingDir, codec);
			System.out.println( "RESULT: " + result );
			fail();
		} catch (Exception e) {
			// expected
		}
		try {
			File exec2 = new File( executable.getPath() + "/../bin/sh" );
			String result = instance.executeSystemCommand(exec2, new ArrayList(params), workingDir, codec);
			System.out.println( "RESULT: " + result );
			fail();
		} catch (Exception e) {
			// expected
		}
		try {
			params.add(";ls");
			String result = instance.executeSystemCommand(executable, new ArrayList(params), workingDir, codec);
			System.out.println( "RESULT: " + result );
		} catch (Exception e) {
			fail();
		}
	}

	public void testExecuteJava() throws Exception
	{
		List params = new ArrayList();
		String result;

		// -version goes to stderr which executeSystemCommand doesn't read...
		// -help goes to stdout so we'll use that...
		params.add("-help");

		result = instance.executeSystemCommand(JAVA_CMD, params, TMP_DIR, codec);
		assertNotNull("result of java -version was null", result);
		assertTrue("result of java -help did not contain -version", result.indexOf("-version") >= 0);
	}

	public void testExecuteJavaSemicolenInject() throws Exception
	{
		List params = new ArrayList();
		File exe;

		exe = new File(JAVA_CMD.getCanonicalPath() + ';' + JAVA_CMD.getCanonicalPath());
		params.add("-help");

		try
		{
			instance.executeSystemCommand(exe, params, TMP_DIR, codec);
			fail("No Exception was thrown when trying to execute " + exe);
		}
		catch(Exception expected)
		{
		}
	}

	public void testExecuteJavaDirectoryTraversal() throws Exception
	{
		List params = new ArrayList();
		File exe;

		exe = new File(JAVA_HOME_BIN.getPath() + File.separator +  ".." + File.separator + "bin" + File.separator + JAVA_CMD_NAME);
		params.add("-help");

		try
		{
			instance.executeSystemCommand(exe, params, TMP_DIR, codec);
			fail("No Exception was thrown when trying to execute " + exe);
		}
		catch(Exception expected)
		{
		}
	}

	public void testExecuteJavaParamSemicolen() throws Exception
	{
		List params = new ArrayList();
		params.add("-help");
		params.add(";" + JAVA_CMD.getPath());

		instance.executeSystemCommand(JAVA_CMD, params, TMP_DIR, codec);
	}

	public void testExecuteJavaBadWorkingDir() throws Exception
	{
		List params = new ArrayList();
		File working;

		params.add("-help");
		working = FileTestUtils.getNonexistantFile();
		try
		{
			instance.executeSystemCommand(JAVA_CMD, params, working, codec);
			fail("Attempt to execute java with invalid working directory should throw exception but didn't.");
		}
		catch(Exception expected)
		{
		}
	}
}
