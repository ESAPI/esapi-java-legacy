package org.owasp.esapi.reference.accesscontrol;

import org.owasp.esapi.AccessControlRule;

abstract public class BaseACR<P, R> implements AccessControlRule<P, R> {

	protected P policyParameters;
	
//	@Override
	public void setPolicyParameters(P policyParameter) {
		this.policyParameters = policyParameter;
	}
	
//	@Override
	public P getPolicyParameters() {
		return policyParameters;
	}
}
