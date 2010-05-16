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
package org.owasp.esapi.filters;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.owasp.esapi.http.MockHttpServletRequest;


/**
 * The Class SafeRequestTest.
 * 
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 */
public class SafeRequestTest extends TestCase {

	/**
	 * Instantiates a new access controller test.
	 * 
	 * @param testName
	 *            the test name
	 * @throws Exception
	 */
	public SafeRequestTest(String testName) throws Exception {
		super(testName);
	}

	/**
	 * {@inheritDoc}
	 *
	 * @throws Exception
	 */
	protected void setUp() throws Exception {
	}

	/**
	 * {@inheritDoc}
	 *
	 * @throws Exception
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
		TestSuite suite = new TestSuite(SafeRequestTest.class);
		return suite;
	}

	/**
	 *
	 */
	public void testGetRequestParameters() {
		System.out.println( "getRequestParameters");
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter( "one","1" );
		request.addParameter( "two","2" );
		request.addParameter( "one","3" );
		request.addParameter( "one","4" );
		SecurityWrapperRequest safeRequest = new SecurityWrapperRequest( request );
		String[] params = safeRequest.getParameterValues("one");
		String out = "";
		for (int i = 0; i < params.length; i++ ) out += params[i];
		assertEquals( "134", out );
	}

	public void testGetQueryStringNull()
	{
		MockHttpServletRequest req = new MockHttpServletRequest();
		SecurityWrapperRequest wrappedReq;

		req.setQueryString(null);
		wrappedReq = new SecurityWrapperRequest(req);
		assertNull(wrappedReq.getQueryString());
	}

	public void testGetQueryStringNonNull()
	{
		MockHttpServletRequest req = new MockHttpServletRequest();
		SecurityWrapperRequest wrappedReq;

		req.setQueryString("a=b");
		wrappedReq = new SecurityWrapperRequest(req);
		assertEquals("a=b",wrappedReq.getQueryString());
	}

	public void testGetQueryStringNUL()
	{
		MockHttpServletRequest req = new MockHttpServletRequest();
		SecurityWrapperRequest wrappedReq;

		req.setQueryString("a=\u0000");
		wrappedReq = new SecurityWrapperRequest(req);
		assertEquals("",wrappedReq.getQueryString());
	}

	public void testGetQueryStringPercent()
	{
		MockHttpServletRequest req = new MockHttpServletRequest();
		SecurityWrapperRequest wrappedReq;

		req.setQueryString("a=%62");
		wrappedReq = new SecurityWrapperRequest(req);
		assertEquals("a=b",wrappedReq.getQueryString());
	}
	
	public void testGetQueryStringPercentNUL()
	{
		MockHttpServletRequest req = new MockHttpServletRequest();
		SecurityWrapperRequest wrappedReq;

		req.setQueryString("a=%00");
		wrappedReq = new SecurityWrapperRequest(req);
		assertEquals("",wrappedReq.getQueryString());
	}

	/* these tests need to be enabled&changed based on the decisions
	 * made regarding issue 125. Currently they fail.
	public void testGetQueryStringPercentEquals()
	{
		MockHttpServletRequest req = new MockHttpServletRequest();
		SecurityWrapperRequest wrappedReq;

		req.setQueryString("a=%3d");
		wrappedReq = new SecurityWrapperRequest(req);
		assertEquals("a=%3d",wrappedReq.getQueryString());
	}

	public void testGetQueryStringPercentAmpersand()
	{
		MockHttpServletRequest req = new MockHttpServletRequest();
		SecurityWrapperRequest wrappedReq;

		req.setQueryString("a=%26b");
		wrappedReq = new SecurityWrapperRequest(req);
		assertEquals("a=%26b",wrappedReq.getQueryString());
	}
	*/

	// Test to ensure null-value contract defined by ServletRequest.getParameterNames(String) is met.
	public void testGetParameterValuesReturnsNullWhenParameterDoesNotExistInRequest() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.clearParameters();
 
		final String paramName = "nonExistentParameter";
		assertNull(request.getParameterValues(paramName));

		SecurityWrapperRequest safeRequest = new SecurityWrapperRequest(request);
		assertNull("Expecting null value to be returned for non-existent parameter.", safeRequest.getParameterValues(paramName));
	}

	public void testGetParameterValuesReturnsCorrectValueWhenParameterExistsInRequest() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.clearParameters();

		final String paramName = "existentParameter";
		final String paramValue = "foobar";
		request.addParameter(paramName, paramValue);
		assertTrue(request.getParameterValues(paramName)[0].equals(paramValue));

		SecurityWrapperRequest safeRequest = new SecurityWrapperRequest(request);
		final String actualParamValue = safeRequest.getParameterValues(paramName)[0];
		assertEquals(paramValue, actualParamValue);
	}

	public void testGetParameterValuesReturnsCorrectValuesWhenParameterExistsMultipleTimesInRequest() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.clearParameters();

		final String paramName = "existentParameter";
		final String paramValue_0 = "foobar";
		final String paramValue_1 = "barfoo";
		request.addParameter(paramName, paramValue_0);
		request.addParameter(paramName, paramValue_1);
		assertTrue(request.getParameterValues(paramName)[0].equals(paramValue_0));
		assertTrue(request.getParameterValues(paramName)[1].equals(paramValue_1));

		SecurityWrapperRequest safeRequest = new SecurityWrapperRequest(request);
		final String[] actualParamValues = safeRequest.getParameterValues(paramName);
		assertEquals(paramValue_0, actualParamValues[0]);
		assertEquals(paramValue_1, actualParamValues[1]);
	}
}
