package org.owasp.esapi.reference;

import junit.framework.Assert;

import org.junit.Test;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Logger;
import org.owasp.esapi.errors.ConfigurationException;

public class DefaultSecurityConfigurationTest {

	private DefaultSecurityConfiguration createWithProperty(String key, String val) {
		java.util.Properties properties = new java.util.Properties();
		properties.setProperty(key, val);
		return new DefaultSecurityConfiguration(properties);
	}
	
	@Test
	public void testGetApplicationName() {
		final String expected = "ESAPI_UnitTests";
		DefaultSecurityConfiguration secConf = this.createWithProperty(DefaultSecurityConfiguration.APPLICATION_NAME, expected);
		Assert.assertEquals(expected, secConf.getApplicationName());
	}
	
	@Test
	public void testGetLogImplementation() {
		//test the default
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		Assert.assertEquals(DefaultSecurityConfiguration.DEFAULT_LOG_IMPLEMENTATION, secConf.getLogImplementation());
		
		final String expected = "TestLogger";
		secConf = this.createWithProperty(DefaultSecurityConfiguration.LOG_IMPLEMENTATION, expected);
		Assert.assertEquals(expected, secConf.getLogImplementation());
	}
	
	@Test
	public void testAuthenticationImplementation() {
		//test the default
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		Assert.assertEquals(DefaultSecurityConfiguration.DEFAULT_AUTHENTICATION_IMPLEMENTATION, secConf.getAuthenticationImplementation());
		
		final String expected = "TestAuthentication";
		secConf = this.createWithProperty(DefaultSecurityConfiguration.AUTHENTICATION_IMPLEMENTATION, expected);
		Assert.assertEquals(expected, secConf.getAuthenticationImplementation());
	}
	
	@Test
	public void testEncoderImplementation() {
		//test the default
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		Assert.assertEquals(DefaultSecurityConfiguration.DEFAULT_ENCODER_IMPLEMENTATION, secConf.getEncoderImplementation());
		
		final String expected = "TestEncoder";
		secConf = this.createWithProperty(DefaultSecurityConfiguration.ENCODER_IMPLEMENTATION, expected);
		Assert.assertEquals(expected, secConf.getEncoderImplementation());
	}
	
	@Test
	public void testAccessControlImplementation() {
		//test the default
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		Assert.assertEquals(DefaultSecurityConfiguration.DEFAULT_ACCESS_CONTROL_IMPLEMENTATION, secConf.getAccessControlImplementation());
		
		final String expected = "TestAccessControl";
		secConf = this.createWithProperty(DefaultSecurityConfiguration.ACCESS_CONTROL_IMPLEMENTATION, expected);
		Assert.assertEquals(expected, secConf.getAccessControlImplementation());
	}
	
	@Test
	public void testEncryptionImplementation() {
		//test the default
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		Assert.assertEquals(DefaultSecurityConfiguration.DEFAULT_ENCRYPTION_IMPLEMENTATION, secConf.getEncryptionImplementation());
		
		final String expected = "TestEncryption";
		secConf = this.createWithProperty(DefaultSecurityConfiguration.ENCRYPTION_IMPLEMENTATION, expected);
		Assert.assertEquals(expected, secConf.getEncryptionImplementation());
	}
	
	@Test
	public void testIntrusionDetectionImplementation() {
		//test the default
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		Assert.assertEquals(DefaultSecurityConfiguration.DEFAULT_INTRUSION_DETECTION_IMPLEMENTATION, secConf.getIntrusionDetectionImplementation());
		
		final String expected = "TestIntrusionDetection";
		secConf = this.createWithProperty(DefaultSecurityConfiguration.INTRUSION_DETECTION_IMPLEMENTATION, expected);
		Assert.assertEquals(expected, secConf.getIntrusionDetectionImplementation());
	}
	
	@Test
	public void testRandomizerImplementation() {
		//test the default
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		Assert.assertEquals(DefaultSecurityConfiguration.DEFAULT_RANDOMIZER_IMPLEMENTATION, secConf.getRandomizerImplementation());
		
		final String expected = "TestRandomizer";
		secConf = this.createWithProperty(DefaultSecurityConfiguration.RANDOMIZER_IMPLEMENTATION, expected);
		Assert.assertEquals(expected, secConf.getRandomizerImplementation());
	}
	
	@Test
	public void testExecutorImplementation() {
		//test the default
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		Assert.assertEquals(DefaultSecurityConfiguration.DEFAULT_EXECUTOR_IMPLEMENTATION, secConf.getExecutorImplementation());
		
		final String expected = "TestExecutor";
		secConf = this.createWithProperty(DefaultSecurityConfiguration.EXECUTOR_IMPLEMENTATION, expected);
		Assert.assertEquals(expected, secConf.getExecutorImplementation());
	}
	
	@Test
	public void testHTTPUtilitiesImplementation() {
		//test the default
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		Assert.assertEquals(DefaultSecurityConfiguration.DEFAULT_HTTP_UTILITIES_IMPLEMENTATION, secConf.getHTTPUtilitiesImplementation());
		
		final String expected = "TestHTTPUtilities";
		secConf = this.createWithProperty(DefaultSecurityConfiguration.HTTP_UTILITIES_IMPLEMENTATION, expected);
		Assert.assertEquals(expected, secConf.getHTTPUtilitiesImplementation());
	}
	
	@Test
	public void testValidationImplementation() {
		//test the default
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		Assert.assertEquals(DefaultSecurityConfiguration.DEFAULT_VALIDATOR_IMPLEMENTATION, secConf.getValidationImplementation());
		
		final String expected = "TestValidation";
		secConf = this.createWithProperty(DefaultSecurityConfiguration.VALIDATOR_IMPLEMENTATION, expected);
		Assert.assertEquals(expected, secConf.getValidationImplementation());
	}
	
	@Test
	public void testGetEncryptionKeyLength() {
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		Assert.assertEquals(128, secConf.getEncryptionKeyLength());
		
		final int expected = 256;
		secConf = this.createWithProperty(DefaultSecurityConfiguration.KEY_LENGTH, String.valueOf(expected));
		Assert.assertEquals(expected, secConf.getEncryptionKeyLength());
	}
	
	@Test
	public void testGetMasterSalt() {
		try {
			DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
			secConf.getMasterSalt();
			Assert.fail("Expected Exception not thrown");
		}
		catch (ConfigurationException ce) {
			Assert.assertNotNull(ce.getMessage());
		}
		
		final String salt = "53081";
		final String property = ESAPI.encoder().encodeForBase64(salt.getBytes(), false);
		java.util.Properties properties = new java.util.Properties();
		properties.setProperty(DefaultSecurityConfiguration.MASTER_SALT, property);
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(properties);
		Assert.assertEquals(salt, new String(secConf.getMasterSalt()));
	}
	
	@Test
	public void testGetAllowedExecutables() {
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		java.util.List<String> allowedExecutables = secConf.getAllowedExecutables();
		
		//is this really what should be returned? what about an empty list?
		Assert.assertEquals(1, allowedExecutables.size());
		Assert.assertEquals("", allowedExecutables.get(0));
		
		
		java.util.Properties properties = new java.util.Properties();
		properties.setProperty(DefaultSecurityConfiguration.APPROVED_EXECUTABLES, String.valueOf("/bin/bzip2,/bin/diff, /bin/cvs"));
		secConf = new DefaultSecurityConfiguration(properties);
		allowedExecutables = secConf.getAllowedExecutables();
		Assert.assertEquals(3, allowedExecutables.size());
		Assert.assertEquals("/bin/bzip2", allowedExecutables.get(0));
		Assert.assertEquals("/bin/diff", allowedExecutables.get(1));
		
		//this seems less than optimal, maybe each value should have a trim() done to it
		//at least we know that this behavior exists, the property should'nt have spaces between values
		Assert.assertEquals(" /bin/cvs", allowedExecutables.get(2));
	}
	
	@Test
	public void testGetAllowedFileExtensions() {
		
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		java.util.List<String> allowedFileExtensions = secConf.getAllowedFileExtensions();
		Assert.assertFalse(allowedFileExtensions.isEmpty());
		
		
		java.util.Properties properties = new java.util.Properties();
		properties.setProperty(DefaultSecurityConfiguration.APPROVED_UPLOAD_EXTENSIONS, String.valueOf(".txt,.xml,.html,.png"));
		secConf = new DefaultSecurityConfiguration(properties);
		allowedFileExtensions = secConf.getAllowedFileExtensions();
		Assert.assertEquals(4, allowedFileExtensions.size());
		Assert.assertEquals(".html", allowedFileExtensions.get(2));
	}
	
	@Test
	public void testGetAllowedFileUploadSize() {
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		//assert that the default is of some reasonable size
		Assert.assertTrue(secConf.getAllowedFileUploadSize() > (1024 * 100));
		
		final int expected = (1024 * 1000);
		secConf = this.createWithProperty(DefaultSecurityConfiguration.MAX_UPLOAD_FILE_BYTES, String.valueOf(expected));
		Assert.assertEquals(expected, secConf.getAllowedFileUploadSize());
	}
	
	@Test
	public void testGetParameterNames() {
		//test the default
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		Assert.assertEquals("password", secConf.getPasswordParameterName());
		Assert.assertEquals("username", secConf.getUsernameParameterName());
		
		java.util.Properties properties = new java.util.Properties();
		properties.setProperty(DefaultSecurityConfiguration.PASSWORD_PARAMETER_NAME, "j_password");
		properties.setProperty(DefaultSecurityConfiguration.USERNAME_PARAMETER_NAME, "j_username");
		secConf = new DefaultSecurityConfiguration(properties);
		Assert.assertEquals("j_password", secConf.getPasswordParameterName());
		Assert.assertEquals("j_username", secConf.getUsernameParameterName());
	}
	
	@Test
	public void testGetEncryptionAlgorithm() {
		//test the default
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		Assert.assertEquals("AES", secConf.getEncryptionAlgorithm());
		
		secConf = this.createWithProperty(DefaultSecurityConfiguration.ENCRYPTION_ALGORITHM, "3DES");
		Assert.assertEquals("3DES", secConf.getEncryptionAlgorithm());
	}
	
	@Test
	public void testGetCipherXProperties() {
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		Assert.assertEquals("AES/CBC/PKCS5Padding", secConf.getCipherTransformation());
		//Assert.assertEquals("AES/CBC/PKCS5Padding", secConf.getC);
		
		java.util.Properties properties = new java.util.Properties();
		properties.setProperty(DefaultSecurityConfiguration.CIPHER_TRANSFORMATION_IMPLEMENTATION, "Blowfish/CFB/ISO10126Padding");
		secConf = new DefaultSecurityConfiguration(properties);
		Assert.assertEquals("Blowfish/CFB/ISO10126Padding", secConf.getCipherTransformation());
		
		secConf.setCipherTransformation("DESede/PCBC/PKCS5Padding");
		Assert.assertEquals("DESede/PCBC/PKCS5Padding", secConf.getCipherTransformation());
		
		secConf.setCipherTransformation(null);//sets it back to default
		Assert.assertEquals("Blowfish/CFB/ISO10126Padding", secConf.getCipherTransformation());
	}
	
	@Test
	public void testIV() {
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		Assert.assertEquals("random", secConf.getIVType());
		try {
			secConf.getFixedIV();
			Assert.fail();
		}
		catch (ConfigurationException ce) {
			Assert.assertNotNull(ce.getMessage());
		}
		
		java.util.Properties properties = new java.util.Properties();
		properties.setProperty(DefaultSecurityConfiguration.IV_TYPE, "fixed");
		properties.setProperty(DefaultSecurityConfiguration.FIXED_IV, "ivValue");
		secConf = new DefaultSecurityConfiguration(properties);
		Assert.assertEquals("fixed", secConf.getIVType());
		Assert.assertEquals("ivValue", secConf.getFixedIV());
		
		properties.setProperty(DefaultSecurityConfiguration.IV_TYPE, "illegal");
		secConf = new DefaultSecurityConfiguration(properties);
		try {
			secConf.getIVType();
			Assert.fail();
		}
		catch (ConfigurationException ce) {
			Assert.assertNotNull(ce.getMessage());
		}
		try {
			secConf.getFixedIV();
			Assert.fail();
		}
		catch (ConfigurationException ce) {
			Assert.assertNotNull(ce.getMessage());
		}
	}
	
	@Test
	public void testGetAllowMultipleEncoding() {
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		Assert.assertFalse(secConf.getAllowMultipleEncoding());
		
		secConf = this.createWithProperty(DefaultSecurityConfiguration.ALLOW_MULTIPLE_ENCODING, "yes");
		Assert.assertTrue(secConf.getAllowMultipleEncoding());
		
		secConf = this.createWithProperty(DefaultSecurityConfiguration.ALLOW_MULTIPLE_ENCODING, "true");
		Assert.assertTrue(secConf.getAllowMultipleEncoding());
		
		secConf = this.createWithProperty(DefaultSecurityConfiguration.ALLOW_MULTIPLE_ENCODING, "no");
		Assert.assertFalse(secConf.getAllowMultipleEncoding());
	}
	
	@Test
	public void testGetDefaultCanonicalizationCodecs() {
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		Assert.assertFalse(secConf.getDefaultCanonicalizationCodecs().isEmpty());
		
		String property = "org.owasp.esapi.codecs.TestCodec1,org.owasp.esapi.codecs.TestCodec2";
		secConf = this.createWithProperty(DefaultSecurityConfiguration.CANONICALIZATION_CODECS, property);
		Assert.assertTrue(secConf.getDefaultCanonicalizationCodecs().contains("org.owasp.esapi.codecs.TestCodec1"));
	}
	
	@Test
	public void testGetDisableIntrusionDetection() {
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		Assert.assertFalse(secConf.getDisableIntrusionDetection());
		
		secConf = this.createWithProperty(DefaultSecurityConfiguration.DISABLE_INTRUSION_DETECTION, "TRUE");
		Assert.assertTrue(secConf.getDisableIntrusionDetection());
		
		secConf = this.createWithProperty(DefaultSecurityConfiguration.DISABLE_INTRUSION_DETECTION, "true");
		Assert.assertTrue(secConf.getDisableIntrusionDetection());
		
		secConf = this.createWithProperty(DefaultSecurityConfiguration.DISABLE_INTRUSION_DETECTION, "false");
		Assert.assertFalse(secConf.getDisableIntrusionDetection());
	}
	
	@Test
	public void testGetLogLevel() {
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		Assert.assertEquals(Logger.WARNING, secConf.getLogLevel());
		
		secConf = this.createWithProperty(DefaultSecurityConfiguration.LOG_LEVEL, "trace");
		Assert.assertEquals(Logger.TRACE, secConf.getLogLevel());
		
		secConf = this.createWithProperty(DefaultSecurityConfiguration.LOG_LEVEL, "Off");
		Assert.assertEquals(Logger.OFF, secConf.getLogLevel());
		
		secConf = this.createWithProperty(DefaultSecurityConfiguration.LOG_LEVEL, "all");
		Assert.assertEquals(Logger.ALL, secConf.getLogLevel());
		
		secConf = this.createWithProperty(DefaultSecurityConfiguration.LOG_LEVEL, "DEBUG");
		Assert.assertEquals(Logger.DEBUG, secConf.getLogLevel());
		
		secConf = this.createWithProperty(DefaultSecurityConfiguration.LOG_LEVEL, "info");
		Assert.assertEquals(Logger.INFO, secConf.getLogLevel());
		
		secConf = this.createWithProperty(DefaultSecurityConfiguration.LOG_LEVEL, "ERROR");
		Assert.assertEquals(Logger.ERROR, secConf.getLogLevel());
	}
	
	@Test
	public void testGetLogFileName() {
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		Assert.assertEquals("ESAPI_logging_file", secConf.getLogFileName());
		
		secConf = this.createWithProperty(DefaultSecurityConfiguration.LOG_FILE_NAME, "log.txt");
		Assert.assertEquals("log.txt", secConf.getLogFileName());
	}
	
	@Test
	public void testGetMaxLogFileSize() {
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		Assert.assertEquals(DefaultSecurityConfiguration.DEFAULT_MAX_LOG_FILE_SIZE, secConf.getMaxLogFileSize());
		
		int maxLogSize = (1024 * 1000);
		secConf = this.createWithProperty(DefaultSecurityConfiguration.MAX_LOG_FILE_SIZE, String.valueOf(maxLogSize));
		Assert.assertEquals(maxLogSize, secConf.getMaxLogFileSize());
	}

	
}
