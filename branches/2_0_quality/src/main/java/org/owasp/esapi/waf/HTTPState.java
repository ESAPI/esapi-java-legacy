package org.owasp.esapi.waf;

public class HTTPState {


	public static final int ID_STATE_BEFORE_BODY = 0;
	public static final int ID_STATE_AFTER_BODY = 1;
	public static final int ID_STATE_BEFORE_RESPONSE = 2;

	public static final HTTPState STATE_BEFORE_BODY = new HTTPState("HTTP_BEFORE_BODY","Rules placed in this phase will be executed when the HTTP request headers have been processed but before the body has been read.");
	public static final HTTPState STATE_AFTER_BODY = new HTTPState("HTTP_AFTER_BODY","Rules placed in this phase will be executed when HTTP request body has been read in but before the request has been sent on to the application.");
	public static final HTTPState STATE_BEFORE_RESPONSE = new HTTPState("HTTP_BEFORE_RESPONSE","Rules placed in this phase will be executed after the HTTP response has been generated but before it has been sent back to the user agent.");

	private String name;
	private String description;

	public HTTPState(String name, String description) {
		this.name = name;
		this.description = description;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getDescription() {
		return description;
	}

	public void setDescription(String description) {
		this.description = description;
	}


}
