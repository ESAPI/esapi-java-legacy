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

import java.lang.reflect.Method;
import java.lang.reflect.InvocationTargetException;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Locale;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Logger;
import org.owasp.esapi.StringUtilities;
import org.owasp.esapi.errors.ValidationException;

/**
 * This response wrapper simply overrides unsafe methods in the
 * HttpServletResponse API with safe versions.
 */
public class SafeResponse extends HttpServletResponseWrapper
{
	private static final Class CLASS = SafeResponse.class;
	private static final Logger logger = ESAPI.getLogger("SafeResponse");
	private static final Method setCharacterEncodingMeth;
	private static final boolean IS_SERVLET_23;

	private HttpServletResponse response;
	private boolean getWriterCalled = false;

	// figure out how to handle setCharacterEncoding
	static
	{
		Method meth;
		boolean isServlet23;

		try
		{
			meth = HttpServletResponse.class.getMethod("setCharacterEncoding", new Class[]{String.class});
			isServlet23 = false;
		}
		catch(NoSuchMethodException ignored)
		{
			// wouldn't it be nice if there were a version
			// of getMethod that didn't throw an exception
			// when the methdo wasn't found?
			meth = null;
			isServlet23 = true;
		}
		setCharacterEncodingMeth = meth;
		IS_SERVLET_23 = isServlet23;
	}

	/**
	 * Construct a safe response that overrides the default response methods
	 * with safer versions.
	 * 
	 * @param response
	 */
	public SafeResponse(HttpServletResponse response) {
		super(response);
		this.response = response;
	}

	/**
	 * Is the servlet spec version 2.3.
	 *
	 * This exists and is package accesible to ease testing.
	 *
	 * @return true if the servlet spec is 2.3. false otherwise.
	 */
	static boolean isServlet23()
	{
		return IS_SERVLET_23;
	}

	/**
	 * {@inheritDoc}
	 * The wrapping just sets a flag that this method has been called
	 * before calling the underlying response.
	 */
	public PrintWriter getWriter() throws IOException
	{
		getWriterCalled = true;
		return response.getWriter();
	}

	/**
	 * Add a cookie to the response after ensuring that there are no encoded or
	 * illegal characters in the name and name and value. This method also sets
	 * the secure and HttpOnly flags on the cookie.
	 */
	public void addCookie(Cookie cookie) {
		String name = cookie.getName();
		String value = cookie.getValue();
		int maxAge = cookie.getMaxAge();
		String domain = cookie.getDomain();
		String path = cookie.getPath();
		addCookie(name, value, maxAge, domain, path);
	}

	/**
	 * Add a cookie to the response after ensuring that there are no encoded or
	 * illegal characters in the name and name and value. This method also sets
	 * the secure and HttpOnly flags on the cookie.
	 */
	public void addCookie(String name, String value, int maxAge, String domain,
			String path) {
		try {
			String cookieName = ESAPI.validator().getValidInput(
					"safeAddCookie", name, "HTTPCookieName", 50, false);
			String cookieValue = ESAPI.validator().getValidInput(
					"safeAddCookie", value, "HTTPCookieValue", 5000, false);

			// create the special cookie header
			// Set-Cookie:<name>=<value>[; <name>=<value>][; expires=<date>][;
			// domain=<domain_name>][; path=<some_path>][; secure][;HttpOnly
			String header = cookieName + "=" + cookieValue;
			if (maxAge != -1)
				header += "; Max-Age=" + maxAge;
			if (domain != null)
				header += "; Domain=" + domain;
			if (path != null)
				header += "; Path=" + path;
			header += "; Secure; HttpOnly";
			response.addHeader("Set-Cookie", header);

		} catch (ValidationException e) {
			logger.warning(Logger.SECURITY, false, 
					"Attempt to set invalid cookie denied", e);
		}
	}

	/**
	 * Add a cookie to the response after ensuring that there are no encoded or
	 * illegal characters in the name.
	 */
	public void addDateHeader(String name, long date) {
		try {
			String safeName = ESAPI.validator().getValidInput( "safeSetDateHeader", name, "HTTPHeaderName", 20, false);
			response.addDateHeader(safeName, date);
		} catch (ValidationException e) {
			logger.warning(Logger.SECURITY, false, "Attempt to set invalid date header name denied", e);
		}
	}

	/**
	 * Add a header to the response after ensuring that there are no encoded or
	 * illegal characters in the name and name and value. This implementation
	 * follows the following recommendation: "A recipient MAY replace any linear
	 * white space with a single SP before interpreting the field value or
	 * forwarding the message downstream."
	 * http://www.w3.org/Protocols/rfc2616/rfc2616-sec2.html#sec2.2
	 */
	public void addHeader(String name, String value) {
		try {
			// TODO: make stripping a global config
			String strippedName = StringUtilities.stripControls(name);
			String strippedValue = StringUtilities.stripControls(value);
			String safeName = ESAPI.validator().getValidInput("addHeader", strippedName, "HTTPHeaderName", 20, false);
			String safeValue = ESAPI.validator().getValidInput("addHeader", strippedValue, "HTTPHeaderValue", 500, false);
			response.setHeader(safeName, safeValue);
		} catch (ValidationException e) {
			logger.warning(Logger.SECURITY, false, "Attempt to add invalid header denied", e);
		}
	}

	/**
	 * Add an int header to the response after ensuring that there are no
	 * encoded or illegal characters in the name and name.
	 */
	public void addIntHeader(String name, int value) {
		try {
			String safeName = ESAPI.validator().getValidInput( "safeSetDateHeader", name, "HTTPHeaderName", 20, false);
			response.addIntHeader(safeName, value);
		} catch (ValidationException e) {
			logger.warning(Logger.SECURITY, false, "Attempt to set invalid int header name denied", e);
		}
	}

	/**
	 * Return the URL without any changes, to prevent disclosure of the
	 * JSESSIONID. The default implementation of this method can add the
	 * JSESSIONID to the URL if support for cookies is not detected. This
	 * exposes the JSESSIONID credential in bookmarks, referer headers, server
	 * logs, and more.
	 * 
	 * @param url
	 * @return original url
	 */
	public String encodeRedirectUrl(String url) {
		return url;
	}

	/**
	 * Return the URL without any changes, to prevent disclosure of the
	 * JSESSIONID The default implementation of this method can add the
	 * JSESSIONID to the URL if support for cookies is not detected. This
	 * exposes the JSESSIONID credential in bookmarks, referer headers, server
	 * logs, and more.
	 * 
	 * @param url
	 * @return original url
	 */
	public String encodeRedirectURL(String url) {
		return url;
	}

	/**
	 * Return the URL without any changes, to prevent disclosure of the
	 * JSESSIONID The default implementation of this method can add the
	 * JSESSIONID to the URL if support for cookies is not detected. This
	 * exposes the JSESSIONID credential in bookmarks, referer headers, server
	 * logs, and more.
	 * 
	 * @param url
	 * @return original url
	 */
	public String encodeUrl(String url) {
		return url;
	}

	/**
	 * Return the URL without any changes, to prevent disclosure of the
	 * JSESSIONID The default implementation of this method can add the
	 * JSESSIONID to the URL if support for cookies is not detected. This
	 * exposes the JSESSIONID credential in bookmarks, referer headers, server
	 * logs, and more.
	 * 
	 * @param url
	 * @return original url
	 */
	public String encodeURL(String url) {
		return url;
	}

	/**
	 * Override the error code with a 200 in order to confound attackers using
	 * automated scanners.
	 */
	public void sendError(int sc) throws IOException {
		response.sendError(HttpServletResponse.SC_OK, getHTTPMessage(sc));
	}

	/**
	 * Override the error code with a 200 in order to confound attackers using
	 * automated scanners. The message is canonicalized and filtered for
	 * dangerous characters.
	 */
	public void sendError(int sc, String msg) throws IOException {
		response.sendError(HttpServletResponse.SC_OK, ESAPI.encoder().encodeForHTML(msg));
	}


	
    /**
     * This method generates a redirect response that can only be used to redirect the browser to safe locations,
     * as configured in the ESAPI security configuration. This method does not that redirect requests can be modified by
     * attackers, so do not rely information contained within redirect requests, and do not include sensitive
     * information in a redirect.
	 */
	public void sendRedirect(String location) throws IOException {
		if (!ESAPI.validator().isValidRedirectLocation("Redirect", location, false)) {
			logger.fatal(Logger.SECURITY, false, "Bad redirect location: " + location );
			throw new IOException("Redirect failed");
		}
		response.sendRedirect(location);
	}

	/**
	 * Varient of {@link #setCharacterEncoding(String)} for the
	 * Servlet 2.3 spec. As this spec does not provide such a method,
	 * an exception is always thrown. This could be emulated for 2.3
	 * but that would require capturing and parsing the content-type.
	 *
	 * This is package accessible to allow for testing.
	 *
	 * @param charset ignored.
	 * @throws UnsupportedOperationException always.
	 */
	void setCharacterEncoding23(String charset)
	{
		throw new UnsupportedOperationException("The Servlet 2.3 spec does not provide javax.servlet.ServletResponse#setCharacterEncoding(String)");
	}

	/**
	 * Varient of {@link #setCharacterEncoding(String)} for the
	 * Servlet 2.4 and higher spec. This calls the response's version
	 * with reflection for source and binary compatability with
	 * version 2.3. If the response has been committed or
	 * {@link #getWriter()} has been called, the response's method
	 * is not invoked as it would ignore such a call according to the
	 * spec.
	 *
	 * This is package accessible to allow for testing.
	 *
	 * @param charset The charset to use.
	 */
	void setCharacterEncoding24Plus(String charset)
	{
		// Don't bother with reflection if the method isn't
		// going to do anything. The spec says that if getWriter()
		// has been called or if the response has been committed,
		// the call to setCharacterEncoding(String) is ignored.
		if(getWriterCalled || isCommitted())
			return;
		try
		{
			// note that this CANNOT be invoked on "this"
			// or you have infinite recursion
			setCharacterEncodingMeth.invoke(response,new String[]{charset});
		}
		catch(IllegalAccessException e)
		{	// checked, shouldn't happen, wrap
			IllegalStateException wrapped = new IllegalStateException("IllegalAccessException calling public HttpServletRequest#setCharacterEncoding(String).");
			// 1.4 doesn't support cause in IllegalStateException construction
			wrapped.initCause(e);
			throw wrapped;
		}
		catch(InvocationTargetException e)
		{	// checked, shouldn't happen, wrap
			Throwable cause = e.getCause();
			IllegalStateException wrapped = new IllegalStateException("Checked exception " + cause.getClass().getName() + " thrown calling HttpServletRequest#setCharacterEncoding(String) which does not throw a checked exception.");
			// 1.4 doesn't support cause in IllegalStateException construction
			wrapped.initCause(cause);
			throw wrapped;
		}
	}

	/**
	 * Sets the character encoding scheme to the ESAPI configured
	 * encoding scheme.
	 * @param charset ignored
	 */
	public void setCharacterEncoding(String charset)
	{
		// Note: This overrides the provided character set and replaces it with the safe
		// encoding scheme set in ESAPI.properties.
		charset = ESAPI.securityConfiguration().getCharacterEncoding();

		if(IS_SERVLET_23)
			setCharacterEncoding23(charset);
		else
			setCharacterEncoding24Plus(charset);
	}

	/**
	 * Add a date header to the response after ensuring that there are no
	 * encoded or illegal characters in the name.
	 */
	public void setDateHeader(String name, long date) {
		try {
			String safeName = ESAPI.validator().getValidInput( "safeSetDateHeader", name, "HTTPHeaderName", 20, false);
			response.setDateHeader(safeName, date);
		} catch (ValidationException e) {
			logger.warning(Logger.SECURITY, false, "Attempt to set invalid date header name denied", e);
		}
	}

	/**
	 * Add a header to the response after ensuring that there are no encoded or
	 * illegal characters in the name and value.
	 * "A recipient MAY replace any linear white space with a single SP before
	 * interpreting the field value or forwarding the message downstream."
	 * http://www.w3.org/Protocols/rfc2616/rfc2616-sec2.html#sec2.2
	 */
	public void setHeader(String name, String value) {
		try {
			String strippedName = StringUtilities.stripControls(name);
			String strippedValue = StringUtilities.stripControls(value);
			String safeName = ESAPI.validator().getValidInput("setHeader", strippedName, "HTTPHeaderName", 20, false);
			String safeValue = ESAPI.validator().getValidInput("setHeader", strippedValue, "HTTPHeaderValue", 500, false);
			response.setHeader(safeName, safeValue);
		} catch (ValidationException e) {
			logger.warning(Logger.SECURITY, false, "Attempt to set invalid header denied", e);
		}
	}

	/**
	 * Add an int header to the response after ensuring that there are no
	 * encoded or illegal characters in the name.
	 */
	public void setIntHeader(String name, int value) {
		try {
			String safeName = ESAPI.validator().getValidInput( "safeSetIntHeader", name, "HTTPHeaderName", 20, false);
			response.setIntHeader(safeName, value);
		} catch (ValidationException e) {
			logger.warning(Logger.SECURITY, false, "Attempt to set invalid int header name denied", e);
		}
	}

	/**
	 * Override the status code with a 200 in order to confound attackers using
	 * automated scanners.
	 */
	public void setStatus(int sc) {
		response.setStatus(HttpServletResponse.SC_OK);
	}

	/**
	 * Override the status code with a 200 in order to confound attackers using
	 * automated scanners. The message is canonicalized and filtered for
	 * dangerous characters.
	 */
	public void setStatus(int sc, String sm) {
		try {
			// setStatus is deprecated so use sendError instead
			sendError(HttpServletResponse.SC_OK, sm);
		} catch (IOException e) {
			logger.warning(Logger.SECURITY, false, "Attempt to set response status failed", e);
		}
	}

	/**
	 * returns a text message for the HTTP response code
	 */
	private String getHTTPMessage(int sc) {
		return "HTTP error code: " + sc;
	}

}
