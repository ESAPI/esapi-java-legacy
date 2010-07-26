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
public class ExecutorTest extends TestCase {

	private SecurityConfiguration origConfig;

	private static class Conf extends SecurityConfigurationWrapper
	{
		private List allowedExes;
		private File workingDir;

		Conf(SecurityConfiguration orig, List allowedExes, File workingDir)
		{
			super(orig);
			this.allowedExes = allowedExes;
			this.workingDir = workingDir;
		}

		@Override
		public List getAllowedExecutables()
		{
			return allowedExes;
		}

		@Override
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

    @Override
    protected void tearDown() throws Exception {
        ESAPI.override(null);
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
		File tmpDir = new File(System.getProperty("java.io.tmpdir")).getCanonicalFile();
		File sysRoot = new File(System.getenv("SystemRoot")).getCanonicalFile();
		File sys32 = new File(sysRoot,"system32").getCanonicalFile();
		File cmd = new File(sys32,"cmd.exe").getCanonicalFile();
		ESAPI.override(
			new Conf(
				ESAPI.securityConfiguration(),
				Collections.singletonList(cmd.getPath()),
				tmpDir
			)
		);

		Codec codec = new WindowsCodec();
		System.out.println("executeSystemCommand");
		Executor instance = ESAPI.executor();
		List params = new ArrayList();
		try {
			params.add("/C");
			params.add("dir");
			String result = instance.executeSystemCommand(cmd, new ArrayList(params) );
			System.out.println( "RESULT: " + result );
			assertTrue(result.length() > 0);
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
		try {
			File exec2 = new File( cmd.getPath() + ";inject.exe" );
			String result = instance.executeSystemCommand(exec2, new ArrayList(params) );
			System.out.println( "RESULT: " + result );
			fail();
		} catch (Exception e) {
			// expected
		}
		try {
			File exec2 = new File( cmd.getPath() + "\\..\\cmd.exe" );
			String result = instance.executeSystemCommand(exec2, new ArrayList(params) );
			System.out.println( "RESULT: " + result );
			fail();
		} catch (Exception e) {
			// expected
		}
		try {
			File workdir = new File( "c:\\ridiculous" );
			String result = instance.executeSystemCommand(cmd, new ArrayList(params), workdir, codec, false );
			System.out.println( "RESULT: " + result );
			fail();
		} catch (Exception e) {
			// expected
		}
		try {
			params.add("&dir");
			String result = instance.executeSystemCommand(cmd, new ArrayList(params) );
			System.out.println( "RESULT: " + result );
		} catch (Exception e) {
			fail();
		}

		try {
			params.set( params.size()-1, "c:\\autoexec.bat" );
			String result = instance.executeSystemCommand(cmd, new ArrayList(params) );
			System.out.println( "RESULT: " + result );
		} catch (Exception e) {
			fail();
		}

		try {
			params.set( params.size()-1, "c:\\autoexec.bat c:\\config.sys" );
			String result = instance.executeSystemCommand(cmd, new ArrayList(params) );
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

		if ( System.getProperty("os.name").indexOf("Windows") != -1 ) {
			System.out.println("executeUnixSystemCommand - on Windows platform, exiting");
			return;
		}

		// FIXME: need more test cases to use this codec
		Codec codec = new UnixCodec();

		// make sure we have what /bin/sh is pointing at in the allowed exes for the test
		// and a usable working dir
		File binSh = new File("/bin/sh").getCanonicalFile();
		ESAPI.override(
			new Conf(
				ESAPI.securityConfiguration(),
				Collections.singletonList(binSh.getPath()),
				new File("/tmp")
			)
		);

		Executor instance = ESAPI.executor();
		File executable = binSh;
		List params = new ArrayList();
		try {
			params.add("-c");
			params.add("ls");
			params.add("/");
			String result = instance.executeSystemCommand(executable, new ArrayList(params) );
			System.out.println( "RESULT: " + result );
			assertTrue(result.length() > 0);
		} catch (Exception e) {
			fail(e.getMessage());
		}
		try {
			File exec2 = new File( executable.getPath() + ";./inject" );
			String result = instance.executeSystemCommand(exec2, new ArrayList(params) );
			System.out.println( "RESULT: " + result );
			fail();
		} catch (Exception e) {
			// expected
		}
		try {
			File exec2 = new File( executable.getPath() + "/../bin/sh" );
			String result = instance.executeSystemCommand(exec2, new ArrayList(params) );
			System.out.println( "RESULT: " + result );
			fail();
		} catch (Exception e) {
			// expected
		}
		try {
			params.add(";ls");
			String result = instance.executeSystemCommand(executable, new ArrayList(params) );
			System.out.println( "RESULT: " + result );
		} catch (Exception e) {
			fail();
		}
	}

}