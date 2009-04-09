package org.owasp.esapi.reference.accesscontrol.policyloader;

import org.owasp.esapi.reference.accesscontrol.BaseACR;
import org.owasp.esapi.reference.accesscontrol.DynaBeanACRParameter;

//public class EchoDynaBeanPolicyParameterACR extends BaseDynaBeanACR {
public class EchoDynaBeanPolicyParameterACR extends BaseACR<DynaBeanACRParameter, Object> {
	/**
	 * Returns true iff runtimeParameter is a Boolean true.
	 * throws ClassCastException if runtimeParameter is not a Boolean.
	 */
	public boolean isAuthorized(Object runtimeParameter) throws ClassCastException{		
		return getPolicyParameters().getBoolean("isTrue");
	}
}