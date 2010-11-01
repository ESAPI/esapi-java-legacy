package org.owasp.esapi.reference;

import java.util.Map;

import org.owasp.esapi.AccessControlRule;
import org.owasp.esapi.AccessController;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Logger;
import org.owasp.esapi.errors.AccessControlException;
import org.owasp.esapi.reference.accesscontrol.policyloader.ACRPolicyFileLoader;
import org.owasp.esapi.reference.accesscontrol.policyloader.PolicyDTO;

public class DefaultAccessController implements AccessController {
	private Map ruleMap;

    private static volatile AccessController singletonInstance = null;

    public static AccessController getInstance() throws AccessControlException {
        if ( singletonInstance == null ) {
            synchronized ( DefaultAccessController.class ) {
                if ( singletonInstance == null ) {
                    singletonInstance = new DefaultAccessController();
                }
            }
        }
        return singletonInstance;
    }

	protected final Logger logger = ESAPI.getLogger("DefaultAccessController");

	private DefaultAccessController() throws AccessControlException {
		ACRPolicyFileLoader policyDescriptor = new ACRPolicyFileLoader();
		PolicyDTO policyDTO = policyDescriptor.load();		
		ruleMap = policyDTO.getAccessControlRules();
	}

    /**
     * {@inheritDoc}
     */
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

    /** {@inheritDoc} */
	public void assertAuthorized(Object key, Object runtimeParameter) throws AccessControlException {
		boolean isAuthorized;
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
	
    /** {@inheritDoc} */
	public void assertAuthorizedForData(String action, Object data)
			throws AccessControlException {
		this.assertAuthorized("AC 1.0 Data", new Object[] {action, data});
	}

	/**
     * {@inheritDoc}
	 * @deprecated
	 */
	public void assertAuthorizedForFile(String filepath)
			throws AccessControlException {
		this.assertAuthorized("AC 1.0 File", new Object[] {filepath});
	}

    /** {@inheritDoc} */
	public void assertAuthorizedForFunction(String functionName)
			throws AccessControlException {
		this.assertAuthorized("AC 1.0 Function", new Object[] {functionName});
	}

    /** {@inheritDoc} */
	public void assertAuthorizedForService(String serviceName)
			throws AccessControlException {
		this.assertAuthorized("AC 1.0 Service", new Object[] {serviceName});
	}

    /** {@inheritDoc} */
	public void assertAuthorizedForURL(String url)
			throws AccessControlException {
		this.assertAuthorized("AC 1.0 URL", new Object[] {url});
	}

    /** {@inheritDoc} */
	public boolean isAuthorizedForData(String action, Object data) {
		return this.isAuthorized("AC 1.0 Data", new Object[] {action, data});
	}

    /** {@inheritDoc} */
	public boolean isAuthorizedForFile(String filepath) {
		return this.isAuthorized("AC 1.0 File", new Object[] {filepath});
	}

    /** {@inheritDoc} */
	public boolean isAuthorizedForFunction(String functionName) {
		return this.isAuthorized("AC 1.0 Function", new Object[] {functionName});
	}

    /** {@inheritDoc} */
	public boolean isAuthorizedForService(String serviceName) {
		return this.isAuthorized("AC 1.0 Service", new Object[] {serviceName});
	}

    /** {@inheritDoc} */
	public boolean isAuthorizedForURL(String url) {
		return this.isAuthorized("AC 1.0 URL", new Object[] {url});
	}
}
