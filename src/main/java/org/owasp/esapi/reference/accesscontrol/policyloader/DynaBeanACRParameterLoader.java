package org.owasp.esapi.reference.accesscontrol.policyloader;

import org.apache.commons.configuration.XMLConfiguration;
import org.owasp.esapi.reference.accesscontrol.DynaBeanACRParameter;

import static org.owasp.esapi.reference.accesscontrol.policyloader.ACRParameterLoaderHelper.getParameterValue;

final public class DynaBeanACRParameterLoader  
	implements ACRParameterLoader<DynaBeanACRParameter> {
	
//	@Override
	public DynaBeanACRParameter getParameters(XMLConfiguration config, int currentRule) throws java.lang.Exception { //TODO reduce the exception
		DynaBeanACRParameter policyParameter = new DynaBeanACRParameter();
		int numberOfParameters = config.getList("AccessControlRules.AccessControlRule(" + currentRule + ").Parameters.Parameter[@name]").size();
		for(int currentParameter = 0; currentParameter < numberOfParameters; currentParameter++) {
			String parameterName = config.getString("AccessControlRules.AccessControlRule(" + currentRule + ").Parameters.Parameter(" + currentParameter + ")[@name]");
			String parameterType = config.getString("AccessControlRules.AccessControlRule(" + currentRule + ").Parameters.Parameter(" + currentParameter + ")[@type]");
			Object parameterValue = getParameterValue(config, currentRule, currentParameter, parameterType);
			policyParameter.set(parameterName, parameterValue);
		}
		policyParameter.lock(); //This line makes the policyParameter read only. 
		
		return policyParameter;
	}
}
