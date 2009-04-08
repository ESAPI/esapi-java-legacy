package org.owasp.esapi.reference.accesscontrol;

import static org.junit.Assert.assertEquals;

import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.owasp.esapi.AccessController;
import org.owasp.esapi.errors.AccessControlException;
import org.owasp.esapi.reference.accesscontrol.AlwaysFalseACR;
import org.owasp.esapi.reference.accesscontrol.AlwaysTrueACR;
import org.owasp.esapi.reference.accesscontrol.DefaultAccessController;

/**
 * Answers the question: is the AccessController itself working properly?
 * @author Mike H. Fauzy
 *
 */
public class AccessControllerTest {
	
	protected AccessController accessController;
		
	@Before
	public void setup() {
		Map accessControlRules = new HashMap(3);
		accessControlRules.put("AlwaysTrue", new AlwaysTrueACR());
		accessControlRules.put("AlwaysFalse", new AlwaysFalseACR());		
		accessControlRules.put("EchoRuntimeParameter", new EchoRuntimeParameterACR());
		accessController = new DefaultAccessController(accessControlRules);
	}
	
	@Test 
	public void isAuthorized() {
		assertEquals("Rule Not Found: null", accessController.isAuthorized(null, null), false);
		assertEquals("Rule Not Found: Invalid Key", accessController.isAuthorized("A key that does not map to a rule", null), false);		

		assertEquals("AlwaysTrue", accessController.isAuthorized("AlwaysTrue", null), true);
		assertEquals("AlwaysFalse", accessController.isAuthorized("AlwaysFalse", null), false);
		
		assertEquals("EchoRuntimeParameter: True", accessController.isAuthorized("EchoRuntimeParameter", new Boolean(true)), true);
		assertEquals("EchoRuntimeParameter: False", accessController.isAuthorized("EchoRuntimeParameter", new Boolean(false)), false);
		assertEquals("EchoRuntimeParameter: ClassCastException", accessController.isAuthorized("EchoRuntimeParameter", "This is not a boolean"), false);
		assertEquals("EchoRuntimeParameter: null Runtime Parameter", accessController.isAuthorized("EchoRuntimeParameter", null), false);
	}
	
	@Test (expected = AccessControlException.class)	 
	public void enforceAuthorizationRuleNotFoundNullKey() throws Exception {		
		accessController.assertAuthorized(null, null);
	}
	@Test (expected = AccessControlException.class)	 
	public void enforceAuthorizationRuleAKeyThatDoesNotMapToARule() throws Exception {		
		accessController.assertAuthorized("A key that does not map to a rule", null);
	}
	
	
	@Test  
	//Should not throw an exception
	public void enforceAuthorizationAlwaysTrue() throws Exception {		
		accessController.assertAuthorized("AlwaysTrue", null);
	}
	
	@Test (expected = AccessControlException.class)	 
	public void enforceAuthorizationAlwaysFalse() throws Exception {		
		accessController.assertAuthorized("AlwaysFalse", null);
	}
	
	/**
	 * Ensure that isAuthorized does nothing if enforceAuthorization 
	 * is called and isAuthorized returns true
	 */
	@Test 
	//Should not throw an exception
	public void enforceAuthorizationEchoRuntimeParameterTrue() throws Exception {
		accessController.assertAuthorized("EchoRuntimeParameter", new Boolean(true));
	}
	
	/**
	 * Ensure that isAuthorized translates into an exception if enforceAuthorization 
	 * is called and isAuthorized returns false
	 */
	@Test (expected = AccessControlException.class)	 
	public void enforceAuthorizationEchoRuntimeParameterFalse() throws Exception {		
		accessController.assertAuthorized("EchoRuntimeParameter", new Boolean(false));
	}
	
	@Test (expected = AccessControlException.class)	 
	public void enforceAuthorizationEchoRuntimeParameterClassCastException() throws Exception {	
		accessController.assertAuthorized("EchoRuntimeParameter", "This is not a boolean");
	}
	
	@Test (expected = AccessControlException.class)	 
	public void enforceAuthorizationEchoRuntimeParameterNullRuntimeParameter() throws Exception {		
		accessController.assertAuthorized("EchoRuntimeParameter", null);
	}
}
