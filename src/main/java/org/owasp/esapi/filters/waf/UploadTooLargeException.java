package org.owasp.esapi.filters.waf;

public class UploadTooLargeException extends Exception {
	public UploadTooLargeException(String s) {
		super(s);
	}
}
