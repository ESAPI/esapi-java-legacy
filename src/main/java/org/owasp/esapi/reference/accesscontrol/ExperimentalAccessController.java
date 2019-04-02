package org.owasp.esapi.reference.accesscontrol;

import java.util.Map;

import org.owasp.esapi.AccessControlRule;
import org.owasp.esapi.AccessController;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Logger;
import org.owasp.esapi.errors.AccessControlException;
import org.owasp.esapi.reference.accesscontrol.policyloader.ACRPolicyFileLoader;
import org.owasp.esapi.reference.accesscontrol.policyloader.PolicyDTO;

public class ExperimentalAccessController implements AccessController {
	private Map ruleMap;

	protected final Logger logger = ESAPI.getLogger("DefaultAccessController");
	
	public ExperimentalAccessController(Map ruleMap) {
		this.ruleMap = ruleMap;	
	}
	public ExperimentalAccessController() throws AccessControlException {
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
	
	/**
	 * @param action
	 * @param data
	 * @throws AccessControlException
	 * @see org.owasp.esapi.reference.accesscontrol.FileBasedACRs#assertAuthorizedForData(java.lang.String, java.lang.Object)
	 * @deprecated
	 */
    @Deprecated
	public void assertAuthorizedForData(String action, Object data)
			throws AccessControlException {
		this.assertAuthorized("AC 1.0 Data", new Object[] {action, data});
	}

	/**
	 * @param filepath
	 * @throws AccessControlException
	 * @see org.owasp.esapi.reference.accesscontrol.FileBasedACRs#assertAuthorizedForFile(java.lang.String)
	 * @deprecated
	 */
    @Deprecated
	public void assertAuthorizedForFile(String filepath)
			throws AccessControlException {
		this.assertAuthorized("AC 1.0 File", new Object[] {filepath});
	}

	/**
	 * @param functionName
	 * @throws AccessControlException
	 * @see org.owasp.esapi.reference.accesscontrol.FileBasedACRs#assertAuthorizedForFunction(java.lang.String)
	 * @deprecated
	 */
    @Deprecated
	public void assertAuthorizedForFunction(String functionName)
			throws AccessControlException {
		this.assertAuthorized("AC 1.0 Function", new Object[] {functionName});
	}

	/**
	 * @param serviceName
	 * @throws AccessControlException
	 * @see org.owasp.esapi.reference.accesscontrol.FileBasedACRs#assertAuthorizedForService(java.lang.String)
	 * @deprecated
	 */
    @Deprecated
	public void assertAuthorizedForService(String serviceName)
			throws AccessControlException {
		this.assertAuthorized("AC 1.0 Service", new Object[] {serviceName});
	}

	/**
	 * @param url
	 * @throws AccessControlException
	 * @see org.owasp.esapi.reference.accesscontrol.FileBasedACRs#assertAuthorizedForURL(java.lang.String)
	 * @deprecated
	 */
    @Deprecated
	public void assertAuthorizedForURL(String url)
			throws AccessControlException {
		this.assertAuthorized("AC 1.0 URL", new Object[] {url});
	}

	/**
	 * @param action
	 * @param data
	 * @return {@code true} if access is permitted; {@code false} otherwise.
	 * @see org.owasp.esapi.reference.accesscontrol.FileBasedACRs#isAuthorizedForData(java.lang.String, java.lang.Object)
	 * @deprecated
	 */
    @Deprecated
	public boolean isAuthorizedForData(String action, Object data) {
		return this.isAuthorized("AC 1.0 Data", new Object[] {action, data});
	}

	/**
	 * @param filepath
     * @return {@code true} if access is permitted; {@code false} otherwise.
	 * @see org.owasp.esapi.reference.accesscontrol.FileBasedACRs#isAuthorizedForFile(java.lang.String)
	 * @deprecated
	 */
    @Deprecated
	public boolean isAuthorizedForFile(String filepath) {
		return this.isAuthorized("AC 1.0 File", new Object[] {filepath});
	}

	/**
	 * @param functionName
     * @return {@code true} if access is permitted; {@code false} otherwise.
	 * @see org.owasp.esapi.reference.accesscontrol.FileBasedACRs#isAuthorizedForFunction(java.lang.String)
	 * @deprecated
	 */
    @Deprecated
	public boolean isAuthorizedForFunction(String functionName) {
		return this.isAuthorized("AC 1.0 Function", new Object[] {functionName});
	}

	/**
	 * @param serviceName
     * @return {@code true} if access is permitted; {@code false} otherwise.
	 * @see org.owasp.esapi.reference.accesscontrol.FileBasedACRs#isAuthorizedForService(java.lang.String)
	 * @deprecated
	 */
    @Deprecated
	public boolean isAuthorizedForService(String serviceName) {
		return this.isAuthorized("AC 1.0 Service", new Object[] {serviceName});
	}

	/**
	 * @param url
     * @return {@code true} if access is permitted; {@code false} otherwise.
	 * @see org.owasp.esapi.reference.accesscontrol.FileBasedACRs#isAuthorizedForURL(java.lang.String)
	 * @deprecated
	 */
    @Deprecated
	public boolean isAuthorizedForURL(String url) {
		return this.isAuthorized("AC 1.0 URL", new Object[] {url});
	}
}
