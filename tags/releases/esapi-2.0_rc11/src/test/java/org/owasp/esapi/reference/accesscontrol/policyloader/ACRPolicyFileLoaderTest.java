package org.owasp.esapi.reference.accesscontrol.policyloader;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.owasp.esapi.AccessController;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.errors.AccessControlException;
/**
 * Answers the question: Is the policy file being loaded properly?
 * @author Mike H. Fauzy
 */
public class ACRPolicyFileLoaderTest {

	protected AccessController accessController;

	@Before
	public void setUp() throws Exception {
		accessController = ESAPI.accessController();
	}

	@Test
	public void testSetup() throws AccessControlException {
		/**
		 * This tests the policy file
		 */
		ACRPolicyFileLoader policyDescriptor = new ACRPolicyFileLoader();
		PolicyDTO policyDTO = policyDescriptor.load();
		Map accessControlRules = policyDTO.getAccessControlRules();
		assertTrue("Some AccessControlRules are loaded", !accessControlRules
				.isEmpty());
		assertTrue("Access Control Map Contains AlwaysTrue", accessControlRules
				.containsKey("AlwaysTrue"));
		assertTrue("Access Control Map Contains AlwaysFalse",
				accessControlRules.containsKey("AlwaysFalse"));
		assertTrue("Access Control Map Contains EchoRuntimeParameter",
				accessControlRules.containsKey("EchoRuntimeParameter"));
		assertTrue("Access Control Map Contains EchoPolicyParameter",
				accessControlRules.containsKey("EchoPolicyParameter"));
	}

	@Test
	public void isAuthorizedEchoPolicyParameter() {
		assertEquals("EchoPolicyParameter", accessController
				.isAuthorized("EchoPolicyParameter", null), true);
		assertEquals("EchoRuntimeParameterClassCastException", accessController
				.isAuthorized("EchoRuntimeParameterClassCastException", null),
				false);
		// Policy parameter value null, empty or missing. (TODO add more fail
		// state tests
		// assertEquals("EchoRuntimeParameterValueNull",
		// accessController.isAuthorized("EchoRuntimeParameterValueNull", null),
		// false);
		// assertEquals("EchoRuntimeParameterValueEmpty",
		// accessController.isAuthorized("EchoRuntimeParameterValueEmpty",
		// null), false);
		// assertEquals("EchoRuntimeParameterValueMissing",
		// accessController.isAuthorized("EchoRuntimeParameterValueMissing",
		// null), false);
	}
	
	@Test(expected = AccessControlException.class)
	public void enforceAuthorizationRuleNotFoundNullKey() throws AccessControlException {
		accessController.assertAuthorized(null, null);
	}
}
