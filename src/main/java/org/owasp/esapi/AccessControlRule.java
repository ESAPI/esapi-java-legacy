package org.owasp.esapi;

import java.util.*;

public interface AccessControlRule<P, R> {
	public void setPolicyParameters(P policyParameter);
	public P getPolicyParameters();
	public boolean isAuthorized(R runtimeParameter) throws Exception;
}
