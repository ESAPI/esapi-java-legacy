package org.owasp.esapi.reference.accesscontrol.policyloader;

import org.apache.commons.configuration.XMLConfiguration;


public interface ACRParameterLoader <T> {
	public abstract T getParameters(XMLConfiguration config, int currentRule)
		throws java.lang.Exception; //TODO this exception could be more specific
}
