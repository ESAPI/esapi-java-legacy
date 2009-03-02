package org.owasp.esapi.filters.waf.internal;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;
import java.util.Locale;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

import org.owasp.esapi.filters.waf.rules.AddHTTPOnlyFlagRule;
import org.owasp.esapi.filters.waf.rules.AddSecureFlagRule;

public class InterceptingHTTPServletResponse extends HttpServletResponseWrapper {

	private PrintWriter pw;
	private InterceptingServletOutputStream isos;
	private String contentType;

	private List<AddSecureFlagRule> addSecureFlagRules = null;
	private List<AddHTTPOnlyFlagRule> addHTTPOnlyFlagRules = null;

	public InterceptingHTTPServletResponse(HttpServletResponse response, boolean intercepting, boolean buffering) throws IOException {
		super(response);
		this.isos = new InterceptingServletOutputStream(response.getOutputStream(), buffering);
		this.pw = new PrintWriter(isos);
	}

	public InterceptingServletOutputStream getInterceptingServletOutputStream() {
		return isos;
	}

	public ServletOutputStream getOutputStream() throws IllegalStateException, IOException {
		return isos;
    }

	public PrintWriter getWriter() throws IOException {
		return pw;
	}

    public String getContentType() {
        return contentType;
    }

    public void setContentType(String s) {
    	contentType = s;
    }

	public void addCookie(Cookie cookie) {

		boolean addSecureFlag = cookie.getSecure();
		boolean addHTTPOnlyFlag = false;

		if ( ! cookie.getSecure() && addSecureFlagRules != null ) {
			for(int i=0;i<addSecureFlagRules.size();i++) {
				AddSecureFlagRule asfr = addSecureFlagRules.get(i);
				if ( asfr.doesCookieMatch(cookie.getName())) {
					addSecureFlag = true;
				}
			}
		}

		if ( addHTTPOnlyFlagRules != null ) {
			for(int i=0;i<addHTTPOnlyFlagRules.size();i++) {
				AddHTTPOnlyFlagRule ashr = addHTTPOnlyFlagRules.get(i);
				if ( ashr.doesCookieMatch(cookie.getName())) {
					addHTTPOnlyFlag = true;
				}
			}
		}

		String cookieValue = createCookieHeader(cookie.getName(),cookie.getValue(),
												cookie.getMaxAge(),cookie.getDomain(),
												cookie.getPath(), addSecureFlag,
												addHTTPOnlyFlag);
		addHeader("Set-Cookie", cookieValue);

		super.addCookie(cookie);

	}

	private String createCookieHeader(String name, String value, int maxAge, String domain, String path, boolean secure, boolean httpOnly) {
        // create the special cookie header instead of creating a Java cookie
        // Set-Cookie:<name>=<value>[; <name>=<value>][; expires=<date>][;
        // domain=<domain_name>][; path=<some_path>][; secure][;HttpOnly
        String header = name + "=" + value;
        header += "; Max-Age=" + maxAge;

        if (domain != null) {
            header += "; Domain=" + domain;
        }
        if (path != null) {
            header += "; Path=" + path;
        }

        if ( secure ) {
        	header += "; Secure";
        }

        if (httpOnly) {
        	header += "; HttpOnly";
        }

        return header;
    }
}
