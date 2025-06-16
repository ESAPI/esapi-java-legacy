package org.owasp.esapi;

import org.junit.Assert;
import org.junit.Test;


public class ESAPIVerifyAllowedMethods {

	@Test (expected = IllegalArgumentException.class)
	public void verifyNulParamThrows() {
		ESAPI.isMethodExplicityEnabled(null);
	}
	
	@Test (expected = IllegalArgumentException.class)
	public void verifyEmptyNoWhitespaceParameterThrows() {
		ESAPI.isMethodExplicityEnabled("");
	}
	
	@Test (expected = IllegalArgumentException.class)
	public void verifyEmptyOnlyWhitespaceParameterThrows() {
		ESAPI.isMethodExplicityEnabled("   ");
	}
	
	@Test (expected = IllegalArgumentException.class)
	public void verifyEmptyOnlyTabWhitespaceParameterThrows() {
		ESAPI.isMethodExplicityEnabled("\t");
	}
	
	@Test (expected = IllegalArgumentException.class)
	public void verifyEmptyOnlyNewlineWhitespaceParameterThrows() {
		ESAPI.isMethodExplicityEnabled("\n");
	}
	
	
	
	@Test (expected = IllegalArgumentException.class)
	public void verifyNonEsapiPackageParameterThrows() {
		ESAPI.isMethodExplicityEnabled("com.myPackage.myScope.method");
	}
	@Test 
	public void verifyUnknownMethodFailsEnableCheck() {
		Assert.assertFalse(ESAPI.isMethodExplicityEnabled("org.owasp.esapi.reference.DefaultEncoder.encodeForSQ"));
	}
	
	@Test 
	public void verifyDefinedRestrictionIsCaught() {
		Assert.assertTrue(ESAPI.isMethodExplicityEnabled("org.owasp.esapi.reference.DefaultEncoder.encodeForSQL"));
	}
	
}
