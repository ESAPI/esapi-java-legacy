/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2010 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @created 2010
 */
package org.owasp.esapi.reference;

import java.io.FileNotFoundException;
import java.io.IOException;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * Unit tests for {@link DefaultSecurityConfiguration}
 */
public class DefaultSecurityConfigurationTest extends TestCase
{
	private static final Class CLASS = DefaultSecurityConfigurationTest.class;
	private DefaultSecurityConfiguration conf;

	protected void setUp() throws Exception
	{
		conf = new DefaultSecurityConfiguration();
	}

	protected void tearDown() throws Exception
	{
		conf = null;
	}

	public static Test suite()
	{
		return new TestSuite(CLASS);
	}

	/**
	 * Verify that a {@link FileNotFoundException} is thrown for a
	 * missing resource and not a NPE.
	 */
	 public void testGetResourceStreamMissing() throws IOException
	 {
	 	try
		{
			conf.getResourceStream("file.that.should.not.exist");
			fail("getResourceStream(\"file.that.should.not.exist\" did not throw a FileNotFoundException");
		}
		catch (FileNotFoundException expected)
		{
			// success
		}
	 }

}
