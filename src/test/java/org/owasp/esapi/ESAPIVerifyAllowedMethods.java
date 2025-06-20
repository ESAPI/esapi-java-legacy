package org.owasp.esapi;

import org.bouncycastle.crypto.modes.CBCModeCipher;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;
import org.owasp.esapi.errors.ConfigurationException;


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
	
	@Test 
	public void testMissingPropertyReturnsFalse() {
		try {
		SecurityConfiguration mockConfig = Mockito.mock(SecurityConfiguration.class);
		Mockito.when(mockConfig.getStringProp("ESAPI.dangerouslyAllowUnsafeMethods.methodNames")).thenThrow(ConfigurationException.class);
		ESAPI.override(mockConfig);
		
		Assert.assertFalse(ESAPI.isMethodExplicityEnabled("org.owasp.esapi.thisValueDoesNotMatter"));
		Mockito.verify(mockConfig, Mockito.times(1)).getStringProp("ESAPI.dangerouslyAllowUnsafeMethods.methodNames");
		} finally {
			ESAPI.override(null);
		}
		
	}
	
}
