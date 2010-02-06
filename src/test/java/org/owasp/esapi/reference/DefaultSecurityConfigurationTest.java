package org.owasp.esapi.reference;

import junit.framework.Assert;

import org.junit.Test;

public class DefaultSecurityConfigurationTest {

	@Test
	public void testGetApplicationName() {
		final String expected = "ESAPI_UnitTests";
		java.util.Properties properties = new java.util.Properties();
		properties.setProperty(DefaultSecurityConfiguration.APPLICATION_NAME, expected);
		
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(properties);
		Assert.assertEquals(expected, secConf.getApplicationName());
	}
	
	@Test
	public void testGetLogImplementation() {
		//test the default
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		Assert.assertEquals(DefaultSecurityConfiguration.DEFAULT_LOG_IMPLEMENTATION, secConf.getLogImplementation());
		
		final String expected = "TestLogger";
		java.util.Properties properties = new java.util.Properties();
		properties.setProperty(DefaultSecurityConfiguration.LOG_IMPLEMENTATION, expected);
		secConf = new DefaultSecurityConfiguration(properties);
		Assert.assertEquals(expected, secConf.getLogImplementation());
	}
	
	@Test
	public void testAuthenticationImplementation() {
		//test the default
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		Assert.assertEquals(DefaultSecurityConfiguration.DEFAULT_AUTHENTICATION_IMPLEMENTATION, secConf.getAuthenticationImplementation());
		
		final String expected = "TestAuthentication";
		java.util.Properties properties = new java.util.Properties();
		properties.setProperty(DefaultSecurityConfiguration.AUTHENTICATION_IMPLEMENTATION, expected);
		secConf = new DefaultSecurityConfiguration(properties);
		Assert.assertEquals(expected, secConf.getAuthenticationImplementation());
	}
	
	@Test
	public void testEncoderImplementation() {
		//test the default
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		Assert.assertEquals(DefaultSecurityConfiguration.DEFAULT_ENCODER_IMPLEMENTATION, secConf.getEncoderImplementation());
		
		final String expected = "TestEncoder";
		java.util.Properties properties = new java.util.Properties();
		properties.setProperty(DefaultSecurityConfiguration.ENCODER_IMPLEMENTATION, expected);
		secConf = new DefaultSecurityConfiguration(properties);
		Assert.assertEquals(expected, secConf.getEncoderImplementation());
	}
	
	@Test
	public void testAccessControlImplementation() {
		//test the default
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		Assert.assertEquals(DefaultSecurityConfiguration.DEFAULT_ACCESS_CONTROL_IMPLEMENTATION, secConf.getAccessControlImplementation());
		
		final String expected = "TestAccessControl";
		java.util.Properties properties = new java.util.Properties();
		properties.setProperty(DefaultSecurityConfiguration.ACCESS_CONTROL_IMPLEMENTATION, expected);
		secConf = new DefaultSecurityConfiguration(properties);
		Assert.assertEquals(expected, secConf.getAccessControlImplementation());
	}
	
	@Test
	public void testEncryptionImplementation() {
		//test the default
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		Assert.assertEquals(DefaultSecurityConfiguration.DEFAULT_ENCRYPTION_IMPLEMENTATION, secConf.getEncryptionImplementation());
		
		final String expected = "TestEncryption";
		java.util.Properties properties = new java.util.Properties();
		properties.setProperty(DefaultSecurityConfiguration.ENCRYPTION_IMPLEMENTATION, expected);
		secConf = new DefaultSecurityConfiguration(properties);
		Assert.assertEquals(expected, secConf.getEncryptionImplementation());
	}
	
	@Test
	public void testIntrusionDetectionImplementation() {
		//test the default
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		Assert.assertEquals(DefaultSecurityConfiguration.DEFAULT_INTRUSION_DETECTION_IMPLEMENTATION, secConf.getIntrusionDetectionImplementation());
		
		final String expected = "TestIntrusionDetection";
		java.util.Properties properties = new java.util.Properties();
		properties.setProperty(DefaultSecurityConfiguration.INTRUSION_DETECTION_IMPLEMENTATION, expected);
		secConf = new DefaultSecurityConfiguration(properties);
		Assert.assertEquals(expected, secConf.getIntrusionDetectionImplementation());
	}
	
	@Test
	public void testRandomizerImplementation() {
		//test the default
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		Assert.assertEquals(DefaultSecurityConfiguration.DEFAULT_RANDOMIZER_IMPLEMENTATION, secConf.getRandomizerImplementation());
		
		final String expected = "TestRandomizer";
		java.util.Properties properties = new java.util.Properties();
		properties.setProperty(DefaultSecurityConfiguration.RANDOMIZER_IMPLEMENTATION, expected);
		secConf = new DefaultSecurityConfiguration(properties);
		Assert.assertEquals(expected, secConf.getRandomizerImplementation());
	}
	
	@Test
	public void testExecutorImplementation() {
		//test the default
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		Assert.assertEquals(DefaultSecurityConfiguration.DEFAULT_EXECUTOR_IMPLEMENTATION, secConf.getExecutorImplementation());
		
		final String expected = "TestExecutor";
		java.util.Properties properties = new java.util.Properties();
		properties.setProperty(DefaultSecurityConfiguration.EXECUTOR_IMPLEMENTATION, expected);
		secConf = new DefaultSecurityConfiguration(properties);
		Assert.assertEquals(expected, secConf.getExecutorImplementation());
	}
	
	@Test
	public void testHTTPUtilitiesImplementation() {
		//test the default
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		Assert.assertEquals(DefaultSecurityConfiguration.DEFAULT_HTTP_UTILITIES_IMPLEMENTATION, secConf.getHTTPUtilitiesImplementation());
		
		final String expected = "TestHTTPUtilities";
		java.util.Properties properties = new java.util.Properties();
		properties.setProperty(DefaultSecurityConfiguration.HTTP_UTILITIES_IMPLEMENTATION, expected);
		secConf = new DefaultSecurityConfiguration(properties);
		Assert.assertEquals(expected, secConf.getHTTPUtilitiesImplementation());
	}
	
	@Test
	public void testValidationImplementation() {
		//test the default
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		Assert.assertEquals(DefaultSecurityConfiguration.DEFAULT_VALIDATOR_IMPLEMENTATION, secConf.getValidationImplementation());
		
		final String expected = "TestValidation";
		java.util.Properties properties = new java.util.Properties();
		properties.setProperty(DefaultSecurityConfiguration.VALIDATOR_IMPLEMENTATION, expected);
		secConf = new DefaultSecurityConfiguration(properties);
		Assert.assertEquals(expected, secConf.getValidationImplementation());
	}
}
