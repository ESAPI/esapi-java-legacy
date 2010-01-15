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


/**
 * The Class ExecutorTest.
 * 
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 */
public class ExecutorTest extends TestCase
{
	private SecurityConfiguration origConfig;

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
		// save configuration as tests may change it
		origConfig = ESAPI.securityConfiguration();
	}

	/**
	 * {@inheritDoc}
	 */
	protected void tearDown() throws Exception {
		// restore configuration as test may change it
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

		if ( System.getProperty("os.name").indexOf("Windows") == -1 ) {
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

		if ( System.getProperty("os.name").indexOf("Windows") != -1 ) {
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

}
