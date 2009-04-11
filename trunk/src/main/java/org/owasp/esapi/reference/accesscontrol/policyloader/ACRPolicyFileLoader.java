package org.owasp.esapi.reference.accesscontrol.policyloader;

import org.apache.commons.configuration.*;
import org.apache.commons.beanutils.*;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Logger;
import org.owasp.esapi.errors.AccessControlException;

import java.io.File;
import java.io.IOException;
import java.util.*;

final public class ACRPolicyFileLoader {
	protected final Logger logger = ESAPI.getLogger("ACRPolicyFileLoader");
	
	public PolicyDTO load() throws AccessControlException {
		PolicyDTO policyDTO = new PolicyDTO();
		XMLConfiguration config;
		File file = ESAPI.securityConfiguration().getResourceFile("ESAPI-AccessControlPolicy.xml"); 
		try
		{
		    config = new XMLConfiguration(file);		    
		}
		catch(ConfigurationException cex)
		{
			if(file == null) {
				throw new AccessControlException("Unable to load configuration file from the following location: " + file, "", cex);
			}
		    throw new AccessControlException("Unable to load configuration file from the following location: " + file.getAbsolutePath(), "", cex);
		} 

		Object property = config.getProperty("AccessControlRules.AccessControlRule[@name]");
		int numberOfRules = 0;
		if(property instanceof Collection) {
			numberOfRules = ((Collection)property).size(); 
		} //TODO MHF, what is the count and class if it's not a collection? 0 or 1?
		
		 
	    try {	    	
	    	logger.error(Logger.EVENT_SUCCESS, "Number of rules: " + numberOfRules);
			String ruleName;
			String ruleClass;
			Object rulePolicyParameter;
			for(int currentRule = 0; currentRule < numberOfRules; currentRule++) {
				logger.error(Logger.EVENT_SUCCESS, "----");
				ruleName = config.getString("AccessControlRules.AccessControlRule(" + currentRule + ")[@name]");
				logger.error(Logger.EVENT_SUCCESS, "Rule name: " + ruleName);
				ruleClass = config.getString("AccessControlRules.AccessControlRule(" + currentRule + ")[@class]");
				logger.error(Logger.EVENT_SUCCESS, "Rule Class: " + ruleClass);
				rulePolicyParameter = getPolicyParameter(config, currentRule);
				logger.error(Logger.EVENT_SUCCESS, "rulePolicyParameters: " + rulePolicyParameter);
				policyDTO.addAccessControlRule(
						ruleName,
						ruleClass,
						rulePolicyParameter);		    	
				logger.error(Logger.EVENT_SUCCESS, "policyDTO: " + policyDTO);
			}			
		} catch (Exception e) {
			e.printStackTrace();
			throw new AccessControlException("Unable to load AccessControlRule parameter", "", e);
		}
		return policyDTO;
	}

	protected Object getPolicyParameter(XMLConfiguration config, int currentRule)
		throws ClassNotFoundException, IllegalAccessException, InstantiationException, Exception {
		//If there aren't any properties: short circuit and return null.
//		Properties tempParameters = config.getProperties("AccessControlRules.AccessControlRule(" + currentRule + ").Parameters.Parameter[@name]");
		Properties tempParameters = config.getProperties("AccessControlRules.AccessControlRule(" + currentRule + ").Parameters.Parameter(1)[@name]");

		if(tempParameters == null ||
			"".equals(tempParameters)) { //tempParameters.size() < 1) {
			return null;
		}
		String parametersLoaderClassName = config.getString("AccessControlRules.AccessControlRule(" + currentRule + ").Parameters[@parametersLoader]");
		if("".equals(parametersLoaderClassName) || parametersLoaderClassName == null) {
			//this default should have a properties file override option
			parametersLoaderClassName = "org.owasp.esapi.reference.accesscontrol.policyloader.DynaBeanACRParameterLoader";
		}
		logger.error(Logger.EVENT_SUCCESS, "Parameters Loader:" + parametersLoaderClassName);
		ACRParameterLoader acrParamaterLoader = 
			(ACRParameterLoader)
			Class.forName(parametersLoaderClassName).newInstance();
		return acrParamaterLoader.getParameters(config, currentRule);		
	}
}