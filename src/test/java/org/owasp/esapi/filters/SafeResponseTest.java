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
 * @created Feb 2010
 */
package org.owasp.esapi.filters;

import java.io.IOException;

import javax.servlet.http.HttpServletResponse;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.owasp.esapi.http.TestHttpServletResponse;

/**
 * Tests for {@link SafeResponse}. Note that there are other
 * tests in {@link org.owasp.esapi.reference.HTTPUtilitiesTest} as
 * well. These tests were not added there as propert testing of
 * {@link SafeResponse#setCharacterEncoding(String)} needs to acces package
 * accessible methods.
 */
public class SafeResponseTest extends TestCase
{
	private static final Class CLASS = SafeResponseTest.class;
	private HttpServletResponse resp;
	private TestHttpServletResponse testResp;
	private SafeResponse safeResp;

	protected void setUp()
	{
		testResp = new TestHttpServletResponse();
		safeResp = new SafeResponse(testResp);
		resp = safeResp;
	}

	protected void tearDown()
	{
		resp = null;
		safeResp = null;
		testResp = null;
	}

	public void testSetCharacterEncoding23()
	{
		try
		{
			safeResp.setCharacterEncoding23("UTF-8");
			fail("setCharacterEncoding23 did not throw a UnsupportedOperationException");
		}
		catch(UnsupportedOperationException expected)
		{
		}
		assertNull("Calling setCharacterEncoding23() resulted in character encoding being set somehow.", testResp.getCharacterEncoding());
	}

	public void testSetCharacterEncoding23Committed()
	{
		try
		{
			testResp.setCommitted();
			safeResp.setCharacterEncoding23("UTF-8");
			fail("setCharacterEncoding23 did not throw a UnsupportedOperationException");
		}
		catch(UnsupportedOperationException expected)
		{
		}
		assertNull("Calling setCharacterEncoding23() resulted in character encoding being set somehow.", testResp.getCharacterEncoding());
	}

	public void testSetCharacterEncoding23AfterGetWriter() throws IOException
	{
		try
		{
			resp.getWriter();
			safeResp.setCharacterEncoding23("UTF-8");
			fail("setCharacterEncoding23 did not throw a UnsupportedOperationException");
		}
		catch(UnsupportedOperationException expected)
		{
		}
		assertNull("Calling setCharacterEncoding23() resulted in character encoding being set somehow.", testResp.getCharacterEncoding());
	}

	public void testSetCharacterEncoding23CommittedAfterGetWriter() throws IOException
	{
		try
		{
			testResp.setCommitted();
			resp.getWriter();
			safeResp.setCharacterEncoding23("UTF-8");
			fail("setCharacterEncoding23 did not throw a UnsupportedOperationException");
		}
		catch(UnsupportedOperationException expected)
		{
		}
		assertNull("Calling setCharacterEncoding23() resulted in character encoding being set somehow.", testResp.getCharacterEncoding());
	}

	public void testSetCharacterEncoding24Plus()
	{
		if(SafeResponse.isServlet23())
			return;	// cannot be tested when not 2.4+
		safeResp.setCharacterEncoding24Plus("UTF-8");
		assertEquals("Calling setCharacterEncoding24Plus() did not result in the character encoding being set", "UTF-8", testResp.getCharacterEncoding());
	}

	public void testSetCharacterEncoding24PlusCommitted()
	{
		if(SafeResponse.isServlet23())
			return;	// cannot be tested when not 2.4+
		testResp.setCommitted();
		safeResp.setCharacterEncoding24Plus("UTF-8");
		assertNull("Calling setCharacterEncoding24Plus() when the response was committed resulted in the character encoding being set anyway.", testResp.getCharacterEncoding());
	}

	public void testSetCharacterEncoding24PlusAfterGetWriter() throws IOException
	{
		if(SafeResponse.isServlet23())
			return;	// cannot be tested when not 2.4+
		resp.getWriter();
		safeResp.setCharacterEncoding24Plus("UTF-8");
		assertNull("Calling setCharacterEncoding24Plus() after getWriter() was called resulted in the character encoding being set anyway.", testResp.getCharacterEncoding());
	}

	public void testSetCharacterEncoding24PlusCommittedAndAfterGetWriter() throws IOException
	{
		if(SafeResponse.isServlet23())
			return;	// cannot be tested when not 2.4+
		resp.getWriter();
		testResp.setCommitted();
		safeResp.setCharacterEncoding24Plus("UTF-8");
		assertNull("Calling setCharacterEncoding24Plus() when the response was committed and getWriter() was called resulted in the character encoding being set anyway.", testResp.getCharacterEncoding());
	}

	public void testSetCharacterEncoding()
	{
		try
		{
			safeResp.setCharacterEncoding("UTF-8");
			assertFalse("UnsupportedOperationException was not thrown when servlet spec version was 2.3", SafeResponse.isServlet23());
			assertEquals("Calling setCharacterEncoding() did not result in the character encoding being set", "UTF-8", testResp.getCharacterEncoding());
		}
		catch(UnsupportedOperationException e)
		{
			assertTrue("UnsupportedOperationException thrown when servlet spec version was not 2.3", SafeResponse.isServlet23());
			assertNull("Calling setCharacterEncoding23() resulted in character encoding being set somehow.", testResp.getCharacterEncoding());
		}
	}

	public void testSetCharacterEncodingCommitted()
	{
		try
		{
			testResp.setCommitted();
			safeResp.setCharacterEncoding("UTF-8");
			assertFalse("UnsupportedOperationException was not thrown when servlet spec version was 2.3", SafeResponse.isServlet23());
			assertNull("Calling setCharacterEncoding() resulted in the character encoding being set even though the request was committed", testResp.getCharacterEncoding());
		}
		catch(UnsupportedOperationException e)
		{
			assertTrue("UnsupportedOperationException thrown when servlet spec version was not 2.3", SafeResponse.isServlet23());
			assertNull("Calling setCharacterEncoding23() resulted in character encoding being set somehow.", testResp.getCharacterEncoding());
		}
	}

	public void testSetCharacterEncodingAfterGetWriter() throws IOException
	{
		try
		{
			resp.getWriter();
			safeResp.setCharacterEncoding("UTF-8");
			assertFalse("UnsupportedOperationException was not thrown when servlet spec version was 2.3", SafeResponse.isServlet23());
			assertNull("Calling setCharacterEncoding() resulted in the character encoding being set even though getWriter() had been called", testResp.getCharacterEncoding());
		}
		catch(UnsupportedOperationException e)
		{
			assertTrue("UnsupportedOperationException thrown when servlet spec version was not 2.3", SafeResponse.isServlet23());
			assertNull("Calling setCharacterEncoding23() resulted in character encoding being set somehow.", testResp.getCharacterEncoding());
		}
	}
	public void testSetCharacterEncodingCommittedAfterGetWriter() throws IOException
	{
		try
		{
			resp.getWriter();
			testResp.setCommitted();
			safeResp.setCharacterEncoding("UTF-8");
			assertFalse("UnsupportedOperationException was not thrown when servlet spec version was 2.3", SafeResponse.isServlet23());
			assertNull("Calling setCharacterEncoding() resulted in the character encoding being set even though getWriter() had been called and the request was committed", testResp.getCharacterEncoding());
		}
		catch(UnsupportedOperationException e)
		{
			assertTrue("UnsupportedOperationException thrown when servlet spec version was not 2.3", SafeResponse.isServlet23());
			assertNull("Calling setCharacterEncoding23() resulted in character encoding being set somehow.", testResp.getCharacterEncoding());
		}
	}

	public static Test suite()
	{
		return new TestSuite(CLASS);
	}
}
