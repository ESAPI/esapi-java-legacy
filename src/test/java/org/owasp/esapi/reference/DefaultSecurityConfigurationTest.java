package org.owasp.esapi.reference;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.regex.Pattern;

import org.junit.Test;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Logger;
import org.owasp.esapi.SecurityConfiguration;
import org.owasp.esapi.errors.ConfigurationException;
import org.owasp.esapi.reference.DefaultSecurityConfiguration.DefaultSearchPath;

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
		assertEquals(expected, secConf.getApplicationName());
	}
	
	@Test
	public void testGetLogImplementation() {
		//test the default
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		assertEquals(DefaultSecurityConfiguration.DEFAULT_LOG_IMPLEMENTATION, secConf.getLogImplementation());
		
		final String expected = "TestLogger";
		secConf = this.createWithProperty(DefaultSecurityConfiguration.LOG_IMPLEMENTATION, expected);
		assertEquals(expected, secConf.getLogImplementation());
	}
	
	@Test
	public void testAuthenticationImplementation() {
		//test the default
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		assertEquals(DefaultSecurityConfiguration.DEFAULT_AUTHENTICATION_IMPLEMENTATION, secConf.getAuthenticationImplementation());
		
		final String expected = "TestAuthentication";
		secConf = this.createWithProperty(DefaultSecurityConfiguration.AUTHENTICATION_IMPLEMENTATION, expected);
		assertEquals(expected, secConf.getAuthenticationImplementation());
	}
	
	@Test
	public void testEncoderImplementation() {
		//test the default
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		assertEquals(DefaultSecurityConfiguration.DEFAULT_ENCODER_IMPLEMENTATION, secConf.getEncoderImplementation());
		
		final String expected = "TestEncoder";
		secConf = this.createWithProperty(DefaultSecurityConfiguration.ENCODER_IMPLEMENTATION, expected);
		assertEquals(expected, secConf.getEncoderImplementation());
	}
	
	@Test
	public void testAccessControlImplementation() {
		//test the default
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		assertEquals(DefaultSecurityConfiguration.DEFAULT_ACCESS_CONTROL_IMPLEMENTATION, secConf.getAccessControlImplementation());
		
		final String expected = "TestAccessControl";
		secConf = this.createWithProperty(DefaultSecurityConfiguration.ACCESS_CONTROL_IMPLEMENTATION, expected);
		assertEquals(expected, secConf.getAccessControlImplementation());
	}
	
	@Test
	public void testEncryptionImplementation() {
		//test the default
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		assertEquals(DefaultSecurityConfiguration.DEFAULT_ENCRYPTION_IMPLEMENTATION, secConf.getEncryptionImplementation());
		
		final String expected = "TestEncryption";
		secConf = this.createWithProperty(DefaultSecurityConfiguration.ENCRYPTION_IMPLEMENTATION, expected);
		assertEquals(expected, secConf.getEncryptionImplementation());
	}
	
	@Test
	public void testIntrusionDetectionImplementation() {
		//test the default
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		assertEquals(DefaultSecurityConfiguration.DEFAULT_INTRUSION_DETECTION_IMPLEMENTATION, secConf.getIntrusionDetectionImplementation());
		
		final String expected = "TestIntrusionDetection";
		secConf = this.createWithProperty(DefaultSecurityConfiguration.INTRUSION_DETECTION_IMPLEMENTATION, expected);
		assertEquals(expected, secConf.getIntrusionDetectionImplementation());
	}
	
	@Test
	public void testRandomizerImplementation() {
		//test the default
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		assertEquals(DefaultSecurityConfiguration.DEFAULT_RANDOMIZER_IMPLEMENTATION, secConf.getRandomizerImplementation());
		
		final String expected = "TestRandomizer";
		secConf = this.createWithProperty(DefaultSecurityConfiguration.RANDOMIZER_IMPLEMENTATION, expected);
		assertEquals(expected, secConf.getRandomizerImplementation());
	}
	
	@Test
	public void testExecutorImplementation() {
		//test the default
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		assertEquals(DefaultSecurityConfiguration.DEFAULT_EXECUTOR_IMPLEMENTATION, secConf.getExecutorImplementation());
		
		final String expected = "TestExecutor";
		secConf = this.createWithProperty(DefaultSecurityConfiguration.EXECUTOR_IMPLEMENTATION, expected);
		assertEquals(expected, secConf.getExecutorImplementation());
	}
	
	@Test
	public void testHTTPUtilitiesImplementation() {
		//test the default
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		assertEquals(DefaultSecurityConfiguration.DEFAULT_HTTP_UTILITIES_IMPLEMENTATION, secConf.getHTTPUtilitiesImplementation());
		
		final String expected = "TestHTTPUtilities";
		secConf = this.createWithProperty(DefaultSecurityConfiguration.HTTP_UTILITIES_IMPLEMENTATION, expected);
		assertEquals(expected, secConf.getHTTPUtilitiesImplementation());
	}
	
	@Test
	public void testValidationImplementation() {
		//test the default
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		assertEquals(DefaultSecurityConfiguration.DEFAULT_VALIDATOR_IMPLEMENTATION, secConf.getValidationImplementation());
		
		final String expected = "TestValidation";
		secConf = this.createWithProperty(DefaultSecurityConfiguration.VALIDATOR_IMPLEMENTATION, expected);
		assertEquals(expected, secConf.getValidationImplementation());
	}
	
	@Test
	public void testGetEncryptionKeyLength() {
		// test the default
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		assertEquals(128, secConf.getEncryptionKeyLength());
		
		final int expected = 256;
		secConf = this.createWithProperty(DefaultSecurityConfiguration.KEY_LENGTH, String.valueOf(expected));
		assertEquals(expected, secConf.getEncryptionKeyLength());
	}
	
	@Test
	public void testGetKDFPseudoRandomFunction() {
		// test the default
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		assertEquals("HmacSHA256", secConf.getKDFPseudoRandomFunction());
		
		final String expected = "HmacSHA1";
		secConf = this.createWithProperty(DefaultSecurityConfiguration.KDF_PRF_ALG, expected);
		assertEquals(expected, secConf.getKDFPseudoRandomFunction());
	}
	
	@Test
	public void testGetMasterSalt() {
		try {
			DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
			secConf.getMasterSalt();
			fail("Expected Exception not thrown");
		}
		catch (ConfigurationException ce) {
			assertNotNull(ce.getMessage());
		}
		
		final String salt = "53081";
		final String property = ESAPI.encoder().encodeForBase64(salt.getBytes(), false);
		java.util.Properties properties = new java.util.Properties();
		properties.setProperty(DefaultSecurityConfiguration.MASTER_SALT, property);
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(properties);
		assertEquals(salt, new String(secConf.getMasterSalt()));
	}
	
	@Test
	public void testGetAllowedExecutables() {
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		java.util.List<String> allowedExecutables = secConf.getAllowedExecutables();
		
		//is this really what should be returned? what about an empty list?
		assertEquals(1, allowedExecutables.size());
		assertEquals("", allowedExecutables.get(0));
		
		
		java.util.Properties properties = new java.util.Properties();
		properties.setProperty(DefaultSecurityConfiguration.APPROVED_EXECUTABLES, String.valueOf("/bin/bzip2,/bin/diff, /bin/cvs"));
		secConf = new DefaultSecurityConfiguration(properties);
		allowedExecutables = secConf.getAllowedExecutables();
		assertEquals(3, allowedExecutables.size());
		assertEquals("/bin/bzip2", allowedExecutables.get(0));
		assertEquals("/bin/diff", allowedExecutables.get(1));
		
		//this seems less than optimal, maybe each value should have a trim() done to it
		//at least we know that this behavior exists, the property should'nt have spaces between values
		assertEquals(" /bin/cvs", allowedExecutables.get(2));
	}
	
	@Test
	public void testGetAllowedFileExtensions() {
		
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		java.util.List<String> allowedFileExtensions = secConf.getAllowedFileExtensions();
		assertFalse(allowedFileExtensions.isEmpty());
		
		
		java.util.Properties properties = new java.util.Properties();
		properties.setProperty(DefaultSecurityConfiguration.APPROVED_UPLOAD_EXTENSIONS, String.valueOf(".txt,.xml,.html,.png"));
		secConf = new DefaultSecurityConfiguration(properties);
		allowedFileExtensions = secConf.getAllowedFileExtensions();
		assertEquals(4, allowedFileExtensions.size());
		assertEquals(".html", allowedFileExtensions.get(2));
	}
	
	@Test
	public void testGetAllowedFileUploadSize() {
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		//assert that the default is of some reasonable size
		assertTrue(secConf.getAllowedFileUploadSize() > (1024 * 100));
		
		final int expected = (1024 * 1000);
		secConf = this.createWithProperty(DefaultSecurityConfiguration.MAX_UPLOAD_FILE_BYTES, String.valueOf(expected));
		assertEquals(expected, secConf.getAllowedFileUploadSize());
	}
	
	@Test
	public void testGetParameterNames() {
		//test the default
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		assertEquals("password", secConf.getPasswordParameterName());
		assertEquals("username", secConf.getUsernameParameterName());
		
		java.util.Properties properties = new java.util.Properties();
		properties.setProperty(DefaultSecurityConfiguration.PASSWORD_PARAMETER_NAME, "j_password");
		properties.setProperty(DefaultSecurityConfiguration.USERNAME_PARAMETER_NAME, "j_username");
		secConf = new DefaultSecurityConfiguration(properties);
		assertEquals("j_password", secConf.getPasswordParameterName());
		assertEquals("j_username", secConf.getUsernameParameterName());
	}
	
	@Test
	public void testGetEncryptionAlgorithm() {
		//test the default
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		assertEquals("AES", secConf.getEncryptionAlgorithm());
		
		secConf = this.createWithProperty(DefaultSecurityConfiguration.ENCRYPTION_ALGORITHM, "3DES");
		assertEquals("3DES", secConf.getEncryptionAlgorithm());
	}
	
	@Test
	public void testGetCipherXProperties() {
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		assertEquals("AES/CBC/PKCS5Padding", secConf.getCipherTransformation());
		//assertEquals("AES/CBC/PKCS5Padding", secConf.getC);
		
		java.util.Properties properties = new java.util.Properties();
		properties.setProperty(DefaultSecurityConfiguration.CIPHER_TRANSFORMATION_IMPLEMENTATION, "Blowfish/CFB/ISO10126Padding");
		secConf = new DefaultSecurityConfiguration(properties);
		assertEquals("Blowfish/CFB/ISO10126Padding", secConf.getCipherTransformation());
		
		secConf.setCipherTransformation("DESede/PCBC/PKCS5Padding");
		assertEquals("DESede/PCBC/PKCS5Padding", secConf.getCipherTransformation());
		
		secConf.setCipherTransformation(null);//sets it back to default
		assertEquals("Blowfish/CFB/ISO10126Padding", secConf.getCipherTransformation());
	}
	
	@Test
	public void testIV() {
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		assertEquals("random", secConf.getIVType());
		try {
			secConf.getFixedIV();
			fail();
		}
		catch (ConfigurationException ce) {
			assertNotNull(ce.getMessage());
		}
		
		java.util.Properties properties = new java.util.Properties();
		properties.setProperty(DefaultSecurityConfiguration.IV_TYPE, "fixed");
		properties.setProperty(DefaultSecurityConfiguration.FIXED_IV, "ivValue");
		secConf = new DefaultSecurityConfiguration(properties);
		assertEquals("fixed", secConf.getIVType());
		assertEquals("ivValue", secConf.getFixedIV());
		
		properties.setProperty(DefaultSecurityConfiguration.IV_TYPE, "illegal");
		secConf = new DefaultSecurityConfiguration(properties);
		try {
			secConf.getIVType();
			fail();
		}
		catch (ConfigurationException ce) {
			assertNotNull(ce.getMessage());
		}
		try {
			secConf.getFixedIV();
			fail();
		}
		catch (ConfigurationException ce) {
			assertNotNull(ce.getMessage());
		}
	}
	
	@Test
	public void testGetAllowMultipleEncoding() {
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		assertFalse(secConf.getAllowMultipleEncoding());
		
		secConf = this.createWithProperty(DefaultSecurityConfiguration.ALLOW_MULTIPLE_ENCODING, "yes");
		assertTrue(secConf.getAllowMultipleEncoding());
		
		secConf = this.createWithProperty(DefaultSecurityConfiguration.ALLOW_MULTIPLE_ENCODING, "true");
		assertTrue(secConf.getAllowMultipleEncoding());
		
		secConf = this.createWithProperty(DefaultSecurityConfiguration.ALLOW_MULTIPLE_ENCODING, "no");
		assertFalse(secConf.getAllowMultipleEncoding());
	}
	
	@Test
	public void testGetDefaultCanonicalizationCodecs() {
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		assertFalse(secConf.getDefaultCanonicalizationCodecs().isEmpty());
		
		String property = "org.owasp.esapi.codecs.TestCodec1,org.owasp.esapi.codecs.TestCodec2";
		secConf = this.createWithProperty(DefaultSecurityConfiguration.CANONICALIZATION_CODECS, property);
		assertTrue(secConf.getDefaultCanonicalizationCodecs().contains("org.owasp.esapi.codecs.TestCodec1"));
	}
	
	@Test
	public void testGetDisableIntrusionDetection() {
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		assertFalse(secConf.getDisableIntrusionDetection());
		
		secConf = this.createWithProperty(DefaultSecurityConfiguration.DISABLE_INTRUSION_DETECTION, "TRUE");
		assertTrue(secConf.getDisableIntrusionDetection());
		
		secConf = this.createWithProperty(DefaultSecurityConfiguration.DISABLE_INTRUSION_DETECTION, "true");
		assertTrue(secConf.getDisableIntrusionDetection());
		
		secConf = this.createWithProperty(DefaultSecurityConfiguration.DISABLE_INTRUSION_DETECTION, "false");
		assertFalse(secConf.getDisableIntrusionDetection());
	}
	
	@Test
	public void testGetLogLevel() {
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		assertEquals(Logger.WARNING, secConf.getLogLevel());
		
		secConf = this.createWithProperty(DefaultSecurityConfiguration.LOG_LEVEL, "trace");
		assertEquals(Logger.TRACE, secConf.getLogLevel());
		
		secConf = this.createWithProperty(DefaultSecurityConfiguration.LOG_LEVEL, "Off");
		assertEquals(Logger.OFF, secConf.getLogLevel());
		
		secConf = this.createWithProperty(DefaultSecurityConfiguration.LOG_LEVEL, "all");
		assertEquals(Logger.ALL, secConf.getLogLevel());
		
		secConf = this.createWithProperty(DefaultSecurityConfiguration.LOG_LEVEL, "DEBUG");
		assertEquals(Logger.DEBUG, secConf.getLogLevel());
		
		secConf = this.createWithProperty(DefaultSecurityConfiguration.LOG_LEVEL, "info");
		assertEquals(Logger.INFO, secConf.getLogLevel());
		
		secConf = this.createWithProperty(DefaultSecurityConfiguration.LOG_LEVEL, "ERROR");
		assertEquals(Logger.ERROR, secConf.getLogLevel());
	}
	
	@Test
	public void testGetLogFileName() {
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		assertEquals("ESAPI_logging_file", secConf.getLogFileName());
		
		secConf = this.createWithProperty(DefaultSecurityConfiguration.LOG_FILE_NAME, "log.txt");
		assertEquals("log.txt", secConf.getLogFileName());
	}
	
	@Test
	public void testGetMaxLogFileSize() {
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(new java.util.Properties());
		assertEquals(DefaultSecurityConfiguration.DEFAULT_MAX_LOG_FILE_SIZE, secConf.getMaxLogFileSize());
		
		int maxLogSize = (1024 * 1000);
		secConf = this.createWithProperty(DefaultSecurityConfiguration.MAX_LOG_FILE_SIZE, String.valueOf(maxLogSize));
		assertEquals(maxLogSize, secConf.getMaxLogFileSize());
	}

    @Test
    public void testNoSuchPropFile(){
        try {
                                        // Do NOT create a file by this name!!! -----vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv
            DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration("NoSuchEsapiPropFileXyzzy.properties");
        }
        catch( ConfigurationException cex ) {
            assertNotNull("Caught exception with null exception msg", cex.getMessage() );
            assertFalse("Exception msg is empty string", cex.getMessage().equals("") );
        }
        catch( Throwable t ) {
            fail("testNoSuchPropFile(): Unexpected exception type: " + t.getClass().getName() + "; ex msg: " + t);
        }

    }
    
	private String patternOrNull(Pattern p){
		return null==p?null:p.pattern();
	}

	@Test
    public void testRootCPLoading(){
        DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration("ESAPI-root-cp.properties");
        assertEquals(patternOrNull(secConf.getValidationPattern("Test1")), "ValueFromFile1");
        assertNull(secConf.getValidationPattern("Test2"));
        assertNull(secConf.getValidationPattern("TestC"));
    }

    @Test
    public void testRootCPLoadingAlt(){
        // This should work also via the class loader.
        DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration("esapi/ESAPI-SingleValidatorFileChecker.properties");
        assertEquals(patternOrNull(secConf.getValidationPattern("Test1")), "ValueFromFile1");
        assertNull(secConf.getValidationPattern("Test2"));
        assertNull(secConf.getValidationPattern("TestC"));
    }

    @Test
    public void testRootCPLoadingAlt2(){
        try {
            // This should fail, because of the '/' on the resourse.
            DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration("/ESAPI-root-cp.properties");
        }
        catch( ConfigurationException cex ) {
            assertNotNull("Caught exception with null exception msg", cex.getMessage() );
            assertFalse("Exception msg is empty string", cex.getMessage().equals("") );
        }
        catch( Throwable t ) {
            fail("testNoSuchPropFile(): Unexpected exception type: " + t.getClass().getName() + "; ex msg: " + t);
        }
    }

    @Test
	public void testValidationsPropertiesFileOptions(){
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration("ESAPI-SingleValidatorFileChecker.properties");
		assertEquals(patternOrNull(secConf.getValidationPattern("Test1")), "ValueFromFile1");
		assertNull(secConf.getValidationPattern("Test2"));
		assertNull(secConf.getValidationPattern("TestC"));
		
		secConf = new DefaultSecurityConfiguration("ESAPI-DualValidatorFileChecker.properties");
		assertEquals(patternOrNull(secConf.getValidationPattern("Test1")), "ValueFromFile1");
		assertEquals(patternOrNull(secConf.getValidationPattern("Test2")), "ValueFromFile2");
		assertNull(secConf.getValidationPattern("TestC"));

		secConf = new DefaultSecurityConfiguration("ESAPI-CommaValidatorFileChecker.properties");
		assertEquals(patternOrNull(secConf.getValidationPattern("TestC")), "ValueFromCommaFile");
		assertNull(secConf.getValidationPattern("Test1"));
		assertNull(secConf.getValidationPattern("Test2"));

		secConf = new DefaultSecurityConfiguration("ESAPI-QuotedValidatorFileChecker.properties");
		assertEquals(patternOrNull(secConf.getValidationPattern("Test1")), "ValueFromFile1");
		assertEquals(patternOrNull(secConf.getValidationPattern("Test2")), "ValueFromFile2");
		assertEquals(patternOrNull(secConf.getValidationPattern("TestC")), "ValueFromCommaFile");
	}
	
	@Test 
	public void DefaultSearchPathTest(){
		assertEquals("", DefaultSearchPath.ROOT.value());
		assertEquals("resourceDirectory/", DefaultSearchPath.RESOURCE_DIRECTORY.value());
		assertEquals(".esapi/", DefaultSearchPath.DOT_ESAPI.value());
		assertEquals("esapi/", DefaultSearchPath.ESAPI.value());
		assertEquals("resources/", DefaultSearchPath.RESOURCES.value());
		assertEquals("src/main/resources/", DefaultSearchPath.SRC_MAIN_RESOURCES.value());
	}
	
	@Test
	public void DefaultSearchPathEnumChanges(){
		int expected = 6;
		int testValue = DefaultSearchPath.values().length;
		assertEquals(expected, testValue);
	}
	
	@Test
	public void defaultPropertiesTest(){
		SecurityConfiguration sc = ESAPI.securityConfiguration();
//		# Maximum size of JSESSIONID for the application--the validator regex may have additional values.  
//		HttpUtilities.HTTPJSESSIONIDLENGTH=50
		assertEquals(50, sc.getIntProp("HttpUtilities.HTTPJSESSIONIDLENGTH"));
//		# Maximum length of a URL (see https://stackoverflow.com/questions/417142/what-is-the-maximum-length-of-a-url-in-different-browsers)
//		HttpUtilities.URILENGTH=2000
		assertEquals(2000, sc.getIntProp("HttpUtilities.URILENGTH"));
//		# Maximum length for an http scheme
//		HttpUtilities.HTTPSCHEMELENGTH=10
		assertEquals(10, sc.getIntProp("HttpUtilities.HTTPSCHEMELENGTH"));
//		# Maximum length for an http host
//		HttpUtilities.HTTPHOSTLENGTH=100
		assertEquals(100, sc.getIntProp("HttpUtilities.HTTPHOSTLENGTH"));
//		# Maximum length for an http path
//		HttpUtilities.HTTPPATHLENGTH=150
		assertEquals(150, sc.getIntProp("HttpUtilities.HTTPPATHLENGTH"));
//		#Maximum length for a context path 
//		HttpUtilities.contextPathLength=150
		assertEquals(150, sc.getIntProp("HttpUtilities.contextPathLength"));
//		#Maximum length for an httpServletPath 
//		HttpUtilities.HTTPSERVLETPATHLENGTH=100
		assertEquals(100, sc.getIntProp("HttpUtilities.HTTPSERVLETPATHLENGTH"));
//		#Maximum length for an http query parameter name
//		HttpUtilities.httpQueryParamNameLength=100
		assertEquals(100, sc.getIntProp("HttpUtilities.httpQueryParamNameLength"));
//		#Maximum length for an http query parameter -- old default was 2000, but that's the max length for a URL...
//		HttpUtilities.httpQueryParamValueLength=500
		assertEquals(500, sc.getIntProp("HttpUtilities.httpQueryParamValueLength"));
//		# Maximum size of HTTP header key--the validator regex may have additional values. 
//		HttpUtilities.MaxHeaderNameSize=256
		assertEquals(256, sc.getIntProp("HttpUtilities.MaxHeaderNameSize"));
//		# Maximum size of HTTP header value--the validator regex may have additional values. 
//		HttpUtilities.MaxHeaderValueSize=4096
		assertEquals(4096, sc.getIntProp("HttpUtilities.MaxHeaderValueSize"));
//		# Maximum length of a redirect 
//		HttpUtilities.maxRedirectLength=512
		assertEquals(512, sc.getIntProp("HttpUtilities.maxRedirectLength"));
	}

    // Test some of the deprecated methods to make sure I didn't screw them up
    // given the double negatives on some these properties.
    @Test
    public void testDeprecatedMethods()
    {
        assertTrue("1: Deprecated (1st) method returns different value than new (2nd) method",
                    ESAPI.securityConfiguration().getDisableIntrusionDetection() ==
                      ESAPI.securityConfiguration().getBooleanProp( DefaultSecurityConfiguration.DISABLE_INTRUSION_DETECTION )
                  );
        // TODO: add some more tests here for the deprecated replacements.
    }
}
