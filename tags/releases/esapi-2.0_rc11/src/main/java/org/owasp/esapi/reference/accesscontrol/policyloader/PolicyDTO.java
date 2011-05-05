package org.owasp.esapi.reference.accesscontrol.policyloader;

import java.lang.reflect.Constructor;
import java.util.HashMap;
import java.util.Map;

import org.owasp.esapi.AccessControlRule;
import org.owasp.esapi.errors.AccessControlException;

/**
 * The point of the loaders is to create this
 * @author Mike H. Fauzy
 *
 */
final public class PolicyDTO {
	private Map accessControlRules;

	public PolicyDTO() {
		this.accessControlRules = new HashMap();
	}
	
	public Map getAccessControlRules() {
		return accessControlRules;
	}

	public void addAccessControlRule(String key, String accessControlRuleClassName,
			Object policyParameter) throws AccessControlException {
		if (accessControlRules.get(key) != null) {
			throw new AccessControlException("Duplicate keys are not allowed. "
					+ "Key: " + key, "");
		}
		Constructor accessControlRuleConstructor;
		try {
			
			
			Class accessControlRuleClass = Class.forName(accessControlRuleClassName, false, this.getClass().getClassLoader());
			accessControlRuleConstructor = accessControlRuleClass
					.getConstructor();
			AccessControlRule accessControlRule = 
				(AccessControlRule) accessControlRuleConstructor
					.newInstance();
			accessControlRule.setPolicyParameters(policyParameter);
			accessControlRules.put(key, accessControlRule);
		} catch (Exception e) {
			throw new AccessControlException(
					"Unable to create Access Control Rule for key: \"" + key
							+ "\" with policyParameters: \"" + policyParameter + "\"",
					"", 
					e);
		}
	}
	public String toString() {
		return accessControlRules.toString();
	}
}
