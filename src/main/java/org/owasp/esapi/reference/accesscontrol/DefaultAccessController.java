package org.owasp.esapi.reference.accesscontrol;

import java.util.*;

import org.owasp.esapi.AccessControlRule;
import org.owasp.esapi.AccessController;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Logger;
import org.owasp.esapi.errors.AccessControlException;
import org.owasp.esapi.reference.FileBasedAccessController;
import org.owasp.esapi.reference.accesscontrol.policyloader.ACRPolicyFileLoader;
import org.owasp.esapi.reference.accesscontrol.policyloader.PolicyDTO;

public class DefaultAccessController implements AccessController {
	private Map ruleMap;

	protected final Logger logger = ESAPI.getLogger("DefaultAccessController");
	
	public DefaultAccessController(Map ruleMap) {
		this.ruleMap = ruleMap;	
	}
	public DefaultAccessController() throws AccessControlException {
		ACRPolicyFileLoader policyDescriptor = new ACRPolicyFileLoader();
		PolicyDTO policyDTO = policyDescriptor.load();		
		ruleMap = policyDTO.getAccessControlRules();
	}
	
	public boolean isAuthorized(Object key, Object runtimeParameter) {
		try {
			AccessControlRule rule = (AccessControlRule)ruleMap.get(key);
			if(rule == null) {
				throw new AccessControlException("Access Denied",
						"AccessControlRule was not found for key: " + key); 
			}
			if(logger.isDebugEnabled()){ logger.debug(Logger.EVENT_SUCCESS, "Evaluating Authorization Rule \"" + key + "\" Using class: " + rule.getClass().getCanonicalName()); }
			return rule.isAuthorized(runtimeParameter);
		} catch(Exception e) {
			try {
				//Log the exception by throwing and then catching it.
				//TODO figure out what which string goes where.		
				throw new AccessControlException("Access Denied",
					"An unhandled Exception was " +
					"caught, so access is denied.",  
					e);	
			} catch(AccessControlException ace) {
				//the exception was just logged. There's nothing left to do.
			}
			return false; //fail closed
		}
	}

	public void assertAuthorized(Object key, Object runtimeParameter)
		throws AccessControlException {
		boolean isAuthorized = false;
		try {
			AccessControlRule rule = (AccessControlRule)ruleMap.get(key);
			if(rule == null) {
				throw new AccessControlException("Access Denied", 
						"AccessControlRule was not found for key: " + key); 
			}
			if(logger.isDebugEnabled()){ logger.debug(Logger.EVENT_SUCCESS, "Asserting Authorization Rule \"" + key + "\" Using class: " + rule.getClass().getCanonicalName()); }
			isAuthorized = rule.isAuthorized(runtimeParameter);
		} catch(Exception e) {
			//TODO figure out what which string goes where.		
			throw new AccessControlException("Access Denied", "An unhandled Exception was " +
					"caught, so access is denied." +
					"AccessControlException.",
					e);
		}
		if(!isAuthorized) {
			throw new AccessControlException("Access Denied", 
					"Access Denied for key: " + key + 
					" runtimeParameter: " + runtimeParameter);
		}
	}

	
	
	
	
	/**** Below this line is legacy support ****/
	
	
	
	
	FileBasedAccessController legacySupport = new FileBasedAccessController();

	/**
	 * @param action
	 * @param data
	 * @throws AccessControlException
	 * @see org.owasp.esapi.reference.FileBasedAccessController#assertAuthorizedForData(java.lang.String, java.lang.Object)
	 * @deprecated
	 */
	public void assertAuthorizedForData(String action, Object data)
			throws AccessControlException {
		legacySupport.assertAuthorizedForData(action, data);
	}

	/**
	 * @param key
	 * @throws AccessControlException
	 * @see org.owasp.esapi.reference.FileBasedAccessController#assertAuthorizedForData(java.lang.String)
	 * @deprecated
	 */
	public void assertAuthorizedForData(String key)
			throws AccessControlException {
		legacySupport.assertAuthorizedForData(key);
	}

	/**
	 * @param filepath
	 * @throws AccessControlException
	 * @see org.owasp.esapi.reference.FileBasedAccessController#assertAuthorizedForFile(java.lang.String)
	 * @deprecated
	 */
	public void assertAuthorizedForFile(String filepath)
			throws AccessControlException {
		legacySupport.assertAuthorizedForFile(filepath);
	}

	/**
	 * @param functionName
	 * @throws AccessControlException
	 * @see org.owasp.esapi.reference.FileBasedAccessController#assertAuthorizedForFunction(java.lang.String)
	 * @deprecated
	 */
	public void assertAuthorizedForFunction(String functionName)
			throws AccessControlException {
		legacySupport.assertAuthorizedForFunction(functionName);
	}

	/**
	 * @param serviceName
	 * @throws AccessControlException
	 * @see org.owasp.esapi.reference.FileBasedAccessController#assertAuthorizedForService(java.lang.String)
	 * @deprecated
	 */
	public void assertAuthorizedForService(String serviceName)
			throws AccessControlException {
		legacySupport.assertAuthorizedForService(serviceName);
	}

	/**
	 * @param url
	 * @throws AccessControlException
	 * @see org.owasp.esapi.reference.FileBasedAccessController#assertAuthorizedForURL(java.lang.String)
	 * @deprecated
	 */
	public void assertAuthorizedForURL(String url)
			throws AccessControlException {
		legacySupport.assertAuthorizedForURL(url);
	}

	/**
	 * @param action
	 * @param data
	 * @return
	 * @see org.owasp.esapi.reference.FileBasedAccessController#isAuthorizedForData(java.lang.String, java.lang.Object)
	 * @deprecated
	 */
	public boolean isAuthorizedForData(String action, Object data) {
		return legacySupport.isAuthorizedForData(action, data);
	}

	/**
	 * @param key
	 * @return
	 * @see org.owasp.esapi.reference.FileBasedAccessController#isAuthorizedForData(java.lang.String)
	 * @deprecated
	 */
	public boolean isAuthorizedForData(String key) {
		return legacySupport.isAuthorizedForData(key);
	}

	/**
	 * @param filepath
	 * @return
	 * @see org.owasp.esapi.reference.FileBasedAccessController#isAuthorizedForFile(java.lang.String)
	 * @deprecated
	 */
	public boolean isAuthorizedForFile(String filepath) {
		return legacySupport.isAuthorizedForFile(filepath);
	}

	/**
	 * @param functionName
	 * @return
	 * @see org.owasp.esapi.reference.FileBasedAccessController#isAuthorizedForFunction(java.lang.String)
	 * @deprecated
	 */
	public boolean isAuthorizedForFunction(String functionName) {
		return legacySupport.isAuthorizedForFunction(functionName);
	}

	/**
	 * @param serviceName
	 * @return
	 * @see org.owasp.esapi.reference.FileBasedAccessController#isAuthorizedForService(java.lang.String)
	 * @deprecated
	 */
	public boolean isAuthorizedForService(String serviceName) {
		return legacySupport.isAuthorizedForService(serviceName);
	}

	/**
	 * @param url
	 * @return
	 * @see org.owasp.esapi.reference.FileBasedAccessController#isAuthorizedForURL(java.lang.String)
	 * @deprecated
	 */
	public boolean isAuthorizedForURL(String url) {
		return legacySupport.isAuthorizedForURL(url);
	}
}
