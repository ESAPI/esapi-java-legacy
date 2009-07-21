/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2007
 */
package org.owasp.esapi.reference;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.owasp.esapi.ESAPI;

/**
 * The Class ExecutorTest.
 * 
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 */
public class SecurityConfigurationTest extends TestCase {

	/**
	 * Instantiates a new executor test.
	 * 
	 * @param testName
	 *            the test name
	 */
	public SecurityConfigurationTest(String testName) {
		super(testName);
	}

	/**
     * {@inheritDoc}
     *
     * @throws Exception
     */
	protected void setUp() throws Exception {
	}

	/**
     * {@inheritDoc}
     *
     * @throws Exception
     */
	protected void tearDown() throws Exception {
		// none
	}

	/**
	 * Suite.
	 * 
	 * @return the test
	 */
	public static Test suite() {
		TestSuite suite = new TestSuite(SecurityConfigurationTest.class);
		return suite;
	}

	public void testGetAccessControlImplementation() { ESAPI.securityConfiguration().getAccessControlImplementation(); }
	public void testGetAllowedExecutables() { ESAPI.securityConfiguration().getAllowedExecutables(); }
	public void testGetAllowedFileExtensions() { ESAPI.securityConfiguration().getAllowedFileExtensions(); }
	public void testGetAllowedFileUploadSize() { ESAPI.securityConfiguration().getAllowedFileUploadSize(); }
	public void testGetAllowedLoginAttempts() { ESAPI.securityConfiguration().getAllowedLoginAttempts(); }
	public void testGetApplicationName() { ESAPI.securityConfiguration().getApplicationName(); }
	public void testGetAuthenticationImplementation() { ESAPI.securityConfiguration().getAuthenticationImplementation(); }
	public void testGetCharacterEncoding() { ESAPI.securityConfiguration().getCharacterEncoding(); }
	public void testGetDigitalSignatureAlgorithm() { ESAPI.securityConfiguration().getDigitalSignatureAlgorithm(); }
	public void testGetDigitalSignatureKeyLength() { ESAPI.securityConfiguration().getDigitalSignatureKeyLength(); }
	public void testGetEncoderImplementation() { ESAPI.securityConfiguration().getEncoderImplementation(); }
	public void testGetEncryptionAlgorithm() { ESAPI.securityConfiguration().getEncryptionAlgorithm(); }
	public void testGetEncryptionImplementation() { ESAPI.securityConfiguration().getEncryptionImplementation(); }
	public void testGetEncryptionKeyLength() { ESAPI.securityConfiguration().getEncryptionKeyLength(); }
	public void testGetExecutorImplementation() { ESAPI.securityConfiguration().getExecutorImplementation(); }
	public void testGetForceHttpOnlySession() { ESAPI.securityConfiguration().getForceHttpOnlySession(); }
	public void testGetForceSecureSession() { ESAPI.securityConfiguration().getForceSecureSession(); }
	public void testGetForceHttpOnlyCookies() { ESAPI.securityConfiguration().getForceHttpOnlyCookies(); }
	public void testGetForceSecureCookies() { ESAPI.securityConfiguration().getForceSecureCookies(); }
	public void testGetHashAlgorithm() { ESAPI.securityConfiguration().getHashAlgorithm(); }
	public void testGetHashIterations() { ESAPI.securityConfiguration().getHashIterations(); }
	public void testGetHTTPUtilitiesImplementation() { ESAPI.securityConfiguration().getHTTPUtilitiesImplementation(); }
	public void testGetIntrusionDetectionImplementation() { ESAPI.securityConfiguration().getIntrusionDetectionImplementation(); }
	public void testGetLogEncodingRequired() { ESAPI.securityConfiguration().getLogEncodingRequired(); }
	public void testGetLogFileName() { ESAPI.securityConfiguration().getLogFileName(); }
	public void testGetLogImplementation() { ESAPI.securityConfiguration().getLogImplementation(); }
	public void testGetLogLevel() { ESAPI.securityConfiguration().getLogLevel(); }
	public void testGetMasterKey() { ESAPI.securityConfiguration().getMasterKey(); }
	public void testGetMasterSalt() { ESAPI.securityConfiguration().getMasterSalt(); }
	public void testGetMaxLogFileSize() { ESAPI.securityConfiguration().getMaxLogFileSize(); }
	public void testGetMaxOldPasswordHashes() { ESAPI.securityConfiguration().getMaxOldPasswordHashes(); }
	public void testGetPasswordParameterName() { ESAPI.securityConfiguration().getPasswordParameterName(); }
	public void testGetQuota() { ESAPI.securityConfiguration().getQuota(null); }
	public void testGetRandomAlgorithm() { ESAPI.securityConfiguration().getRandomAlgorithm(); }
	public void testGetRandomizerImplementation() { ESAPI.securityConfiguration().getRandomizerImplementation(); }
	public void testGetRememberTokenDuration() { ESAPI.securityConfiguration().getRememberTokenDuration(); }
	public void testGetResourceFile() { ESAPI.securityConfiguration().getResourceFile(null); }
	public void testGetResourceStream() throws Exception { ESAPI.securityConfiguration().getResourceStream(null); }
	public void testGetResponseContentType() { ESAPI.securityConfiguration().getResponseContentType(); }
	public void testGetSessionAbsoluteTimeoutLength() { ESAPI.securityConfiguration().getSessionAbsoluteTimeoutLength(); }
	public void testGetSessionIdleTimeoutLength() { ESAPI.securityConfiguration().getSessionIdleTimeoutLength(); }
	public void testGetUploadDirectory() { ESAPI.securityConfiguration().getUploadDirectory(); }
	public void testGetUsernameParameterName() { ESAPI.securityConfiguration().getUsernameParameterName(); }
	public void testGetValidationImplementation() { ESAPI.securityConfiguration().getValidationImplementation(); }
	public void testGetValidationPattern() { ESAPI.securityConfiguration().getValidationPattern(null); }
	public void testGetWorkingDirectory() { ESAPI.securityConfiguration().getWorkingDirectory(); }
	public void testSetResourceDirectory() { ESAPI.securityConfiguration().setResourceDirectory("foo"); }
}
