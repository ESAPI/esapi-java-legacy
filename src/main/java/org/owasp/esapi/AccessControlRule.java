package org.owasp.esapi;


public interface AccessControlRule<P, R> {
	void setPolicyParameters(P policyParameter);
	P getPolicyParameters();
	boolean isAuthorized(R runtimeParameter) throws Exception;
}
