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
		logger.info(Logger.EVENT_SUCCESS, "Loading Property: " + property);
		int numberOfRules = 0;
		if(property instanceof Collection) {
			numberOfRules = ((Collection)property).size();
		} //implied else property == null -> return new PolicyDTO
				 
		String ruleName = "";
		String ruleClass = "";
		Object rulePolicyParameter = null;
		int currentRule = 0;
	    try {	    	
	    	logger.info(Logger.EVENT_SUCCESS, "Number of rules: " + numberOfRules);
			for(currentRule = 0; currentRule < numberOfRules; currentRule++) {
				logger.trace(Logger.EVENT_SUCCESS, "----");
				ruleName = config.getString("AccessControlRules.AccessControlRule(" + currentRule + ")[@name]");
				logger.trace(Logger.EVENT_SUCCESS, "Rule name: " + ruleName);
				ruleClass = config.getString("AccessControlRules.AccessControlRule(" + currentRule + ")[@class]");
				logger.trace(Logger.EVENT_SUCCESS, "Rule Class: " + ruleClass);
				rulePolicyParameter = getPolicyParameter(config, currentRule);
				logger.trace(Logger.EVENT_SUCCESS, "rulePolicyParameters: " + rulePolicyParameter);
				policyDTO.addAccessControlRule(
						ruleName,
						ruleClass,
						rulePolicyParameter);		    	
			}
			logger.info(Logger.EVENT_SUCCESS, "policyDTO loaded: " + policyDTO);
		} catch (Exception e) {
			e.printStackTrace();
			throw new AccessControlException("Unable to load AccessControlRule parameter. " + 
					" Rule number: " + currentRule + 
					" Probably: Rule.name: " + ruleName +
					" Probably: Rule.class: " + ruleClass +
					e.getMessage(), "", e);
		}
		return policyDTO;
	}

	protected Object getPolicyParameter(XMLConfiguration config, int currentRule)
		throws ClassNotFoundException, IllegalAccessException, InstantiationException, Exception {
		//If there aren't any properties: short circuit and return null.
//		Properties tempParameters = config.getProperties("AccessControlRules.AccessControlRule(" + currentRule + ").Parameters.Parameter[@name]");
		Object property = config.getProperty("AccessControlRules.AccessControlRule(" + currentRule + ").Parameters.Parameter[@name]");
		if(property == null) {
			return null;
		}
		
		int numberOfProperties = 0;		
		if(property instanceof Collection) {
			numberOfProperties = ((Collection)property).size(); 
		} else {
			numberOfProperties = 1;
		}
		logger.info(Logger.EVENT_SUCCESS, "Number of properties: " + numberOfProperties);
		
		if(numberOfProperties < 1) {
			return null;
		}
		String parametersLoaderClassName = config.getString("AccessControlRules.AccessControlRule(" + currentRule + ").Parameters[@parametersLoader]");
		if("".equals(parametersLoaderClassName) || parametersLoaderClassName == null) {
			//this default should have a properties file override option
			parametersLoaderClassName = "org.owasp.esapi.reference.accesscontrol.policyloader.DynaBeanACRParameterLoader";
		}
		logger.info(Logger.EVENT_SUCCESS, "Parameters Loader:" + parametersLoaderClassName);
		ACRParameterLoader acrParamaterLoader = 
			(ACRParameterLoader)
			Class.forName(parametersLoaderClassName).newInstance();
		return acrParamaterLoader.getParameters(config, currentRule);		
	}
}