package org.owasp.esapi.waf.internal;

public class Parameter {

	private String name;
	private String value;
	private boolean fromMultipart;

	public Parameter(String name, String value, boolean fromMultipart) {
		this.name = name;
		this.value = value;
		this.fromMultipart = fromMultipart;
	}

	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public String getValue() {
		return value;
	}
	public void setValue(String value) {
		this.value = value;
	}

}
