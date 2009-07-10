package org.owasp.esapi.waf;

public class UploadTooLargeException extends Exception {
    protected static final long serialVersionUID = 1L;
	public UploadTooLargeException(String s) {
		super(s);
	}
}
