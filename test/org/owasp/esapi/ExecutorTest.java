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
import java.util.ArrayList;
import java.util.List;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.owasp.esapi.interfaces.IExecutor;

/**
 * The Class ExecutorTest.
 * 
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 */
public class ExecutorTest extends TestCase {

	/**
	 * Instantiates a new executor test.
	 * 
	 * @param testName
	 *            the test name
	 */
	public ExecutorTest(String testName) {
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
		TestSuite suite = new TestSuite(ExecutorTest.class);
		return suite;
	}

	/**
	 * Test of executeOSCommand method, of class org.owasp.esapi.Executor
	 * 
	 * @throws Exception
	 *             the exception
	 */
	public void testExecuteSystemCommand() throws Exception {
		System.out.println("executeSystemCommand");
		IExecutor instance = ESAPI.executor();
		File executable = new File( "C:\\Windows\\System32\\cmd.exe" );
		File working = new File("C:\\");
		List params = new ArrayList();
		try {
			params.add("/C");
			params.add("dir");
			String result = instance.executeSystemCommand(executable, new ArrayList(params), working, 10);
			assertTrue(result.length() > 0);
		} catch (Exception e) {
			fail();
		}
		try {
			File exec2 = new File( executable.getPath() + ";inject.exe" );
			instance.executeSystemCommand(exec2, new ArrayList(params), working, 10);
			fail();
		} catch (Exception e) {
			// expected
		}
		try {
			File exec2 = new File( executable.getPath() + "\\..\\cmd.exe" );
			instance.executeSystemCommand(exec2, new ArrayList(params), working, 10);
			fail();
		} catch (Exception e) {
			// expected
		}
		try {
			File workdir = new File( "ridiculous" );
			instance.executeSystemCommand(executable, new ArrayList(params), workdir, 10);
			fail();
		} catch (Exception e) {
			// expected
		}
		try {
			params.add("&dir");
			instance.executeSystemCommand(executable, new ArrayList(params), working, 10);
			fail();
		} catch (Exception e) {
			// expected
		}
	}

}
