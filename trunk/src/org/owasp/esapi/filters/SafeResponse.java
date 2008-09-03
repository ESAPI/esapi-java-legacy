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

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Locale;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Logger;
import org.owasp.esapi.StringUtilities;
import org.owasp.esapi.errors.ValidationException;

/**
 * This response wrapper simply overrides unsafe methods in the
 * HttpServletResponse API with safe versions.
 */
public class SafeResponse implements HttpServletResponse {

	private HttpServletResponse response;
	private final Logger logger = ESAPI.getLogger("SafeResponse");

	/**
	 * Construct a safe response that overrides the default response methods
	 * with safer versions.
	 * 
	 * @param response
	 */
	public SafeResponse(HttpServletResponse response) {
		this.response = response;
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
			logger.warning(Logger.SECURITY,
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
			logger.warning(Logger.SECURITY, "Attempt to set invalid date header name denied", e);
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
			logger.warning(Logger.SECURITY, "Attempt to add invalid header denied", e);
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
			logger.warning(Logger.SECURITY, "Attempt to set invalid int header name denied", e);
		}
	}

	/**
	 * Same as HttpServletResponse, no security changes required.
	 */
	public boolean containsHeader(String name) {
		return response.containsHeader(name);
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
	 * Same as HttpServletResponse, no security changes required.
	 */
	public void flushBuffer() throws IOException {
		response.flushBuffer();
	}

	/**
	 * Same as HttpServletResponse, no security changes required.
	 */
	public int getBufferSize() {
		return response.getBufferSize();
	}

	/**
	 * Same as HttpServletResponse, no security changes required.
	 */
	public String getCharacterEncoding() {
		return response.getCharacterEncoding();
	}

	/**
	 * Same as HttpServletResponse, no security changes required.
	 */
	public String getContentType() {
		return response.getContentType();
	}

	/**
	 * Same as HttpServletResponse, no security changes required.
	 */
	public Locale getLocale() {
		return response.getLocale();
	}

	/**
	 * Same as HttpServletResponse, no security changes required.
	 */
	public ServletOutputStream getOutputStream() throws IOException {
		return response.getOutputStream();
	}

	/**
	 * Same as HttpServletResponse, no security changes required.
	 */
	public PrintWriter getWriter() throws IOException {
		return response.getWriter();
	}

	/**
	 * Same as HttpServletResponse, no security changes required.
	 */
	public boolean isCommitted() {
		return response.isCommitted();
	}

	/**
	 * Same as HttpServletResponse, no security changes required.
	 */
	public void reset() {
		response.reset();
	}

	/**
	 * Same as HttpServletResponse, no security changes required.
	 */
	public void resetBuffer() {
		response.resetBuffer();
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
			logger.fatal(Logger.SECURITY, "Bad redirect location: " + location );
			throw new IOException("Redirect failed");
		}
		response.sendRedirect(location);
	}

	/**
	 * Same as HttpServletResponse, no security changes required.
	 */
	public void setBufferSize(int size) {
		response.setBufferSize(size);
	}

	/**
	 * Sets the character encoding to the ESAPI configured encoding.
	 */
	public void setCharacterEncoding(String charset) {
		response.setCharacterEncoding( ESAPI.securityConfiguration().getCharacterEncoding() );
	}

	/**
	 * Same as HttpServletResponse, no security changes required.
	 */
	public void setContentLength(int len) {
		response.setContentLength(len);
	}

	/**
	 * Same as HttpServletResponse, no security changes required.
	 */
	public void setContentType(String type) {
		response.setContentType(type);
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
			logger.warning(Logger.SECURITY, "Attempt to set invalid date header name denied", e);
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
			logger.warning(Logger.SECURITY, "Attempt to set invalid header denied", e);
		}
	}

	/**
	 * Add an int header to the response after ensuring that there are no
	 * encoded or illegal characters in the name.
	 */
	public void setIntHeader(String name, int value) {
		try {
			String safeName = ESAPI.validator().getValidInput( "safeSetDateHeader", name, "HTTPHeaderName", 20, false);
			response.setIntHeader(safeName, value);
		} catch (ValidationException e) {
			logger.warning(Logger.SECURITY, "Attempt to set invalid int header name denied", e);
		}
	}

	/**
	 * Same as HttpServletResponse, no security changes required.
	 */
	public void setLocale(Locale loc) {
		// TODO investigate the character set issues here
		response.setLocale(loc);
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
			logger.warning(Logger.SECURITY, "Attempt to set response status failed", e);
		}
	}

	/**
	 * returns a text message for the HTTP response code
	 */
	private String getHTTPMessage(int sc) {
		return "HTTP error code: " + sc;
	}

}
