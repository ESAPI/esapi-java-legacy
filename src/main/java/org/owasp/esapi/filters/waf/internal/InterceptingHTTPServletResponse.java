package org.owasp.esapi.filters.waf.internal;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

public class InterceptingHTTPServletResponse extends HttpServletResponseWrapper {

	private PrintWriter pw;
	private InterceptingServletOutputStream isos;
	private boolean intercepting;
	private String contentType;

	public InterceptingHTTPServletResponse(HttpServletResponse response, boolean intercepting, boolean buffering) throws IOException {
		super(response);
		this.intercepting = intercepting;
		this.isos = new InterceptingServletOutputStream(response.getOutputStream(), buffering);
		this.pw = new PrintWriter(isos);
	}

	public InterceptingServletOutputStream getInterceptingServletOutputStream() {
		return isos;
	}

	public ServletOutputStream getOutputStream() throws IllegalStateException, IOException {
        if ( intercepting ) {
            return isos;
        }

        return super.getOutputStream();
    }

	public PrintWriter getWriter() throws IOException {
		if ( intercepting ) {
			return pw;
		}
		return super.getWriter();
	}

    public String getContentType() {
        if (intercepting) {
            return contentType;
        }
        return super.getContentType();
    }

    public void setContentType(String s) {
    	if ( intercepting ) {
    		contentType = s;
    	} else {
    		super.setContentType(s);
    	}
    }

}
