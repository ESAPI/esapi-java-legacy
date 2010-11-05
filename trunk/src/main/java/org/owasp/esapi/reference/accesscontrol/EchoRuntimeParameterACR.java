package org.owasp.esapi.reference.accesscontrol;

public class EchoRuntimeParameterACR extends BaseACR<Object, Boolean>{

	/**
	 * Returns true iff runtimeParameter is a Boolean true.
	 * throws ClassCastException if runtimeParameter is not a Boolean.
	 */
	public boolean isAuthorized(Boolean runtimeParameter) throws ClassCastException{
		return runtimeParameter.booleanValue();
	}

}