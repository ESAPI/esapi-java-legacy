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
package org.owasp.esapi;

import junit.framework.Assert;
import junit.framework.JUnit4TestAdapter;

import org.junit.Test;
import org.owasp.esapi.reference.DefaultAccessController;
import org.owasp.esapi.reference.DefaultEncoder;
import org.owasp.esapi.reference.DefaultExecutor;
import org.owasp.esapi.reference.DefaultHTTPUtilities;
import org.owasp.esapi.reference.DefaultIntrusionDetector;
import org.owasp.esapi.reference.DefaultRandomizer;
import org.owasp.esapi.reference.DefaultValidator;
import org.owasp.esapi.reference.FileBasedAuthenticator;
import org.owasp.esapi.reference.JavaEncryptor;
import org.owasp.esapi.reference.JavaLogFactory;

/**
 * The Class ExecutorTest.
 * 
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 */
public class ESAPITest {

	
	/**
	 * Suite.
	 * 
	 * @return the test
	 */
	public static junit.framework.Test suite() {
		return new JUnit4TestAdapter(ESAPITest.class);
	}

	@Test
	public void testSetAuthenticator() throws Exception {

		Authenticator authenticator1 = ESAPI.authenticator();
		Assert.assertSame(authenticator1, ESAPI.setAuthenticator(authenticator1));
		
		Authenticator authenticator2 = new FileBasedAuthenticator();
		Assert.assertSame(authenticator1, ESAPI.setAuthenticator(authenticator2));
		Assert.assertSame(authenticator2, ESAPI.authenticator());
	}
	
	@Test
	public void testSetAccessController() throws Exception {

		ESAPI.setAccessController(null);
		AccessController accessController1 = new DefaultAccessController();
		Assert.assertNull(ESAPI.setAccessController(accessController1));
		
		AccessController accessController2 = new DefaultAccessController();
		Assert.assertSame(accessController1, ESAPI.setAccessController(accessController2));
		Assert.assertSame(accessController2, ESAPI.accessController());
	}
	
	@Test
	public void testSetEncoder() throws Exception {
		
		Encoder encoder1 = ESAPI.encoder();
		Assert.assertSame(encoder1, ESAPI.setEncoder(encoder1));
		
		Encoder encoder2 = new DefaultEncoder();
		Assert.assertSame(encoder1, ESAPI.setEncoder(encoder2));
		Assert.assertSame(encoder2, ESAPI.encoder());
	}
	
	@Test
	public void testSetEncryptor() throws Exception {
		
		Encryptor encryptor1 = ESAPI.encryptor();
		Assert.assertSame(encryptor1, ESAPI.setEncryptor(encryptor1));
		
		Encryptor encryptor2 = new JavaEncryptor();
		Assert.assertNotSame(encryptor1, encryptor2);
		Assert.assertSame(encryptor1, ESAPI.setEncryptor(encryptor2));
		Assert.assertSame(encryptor2, ESAPI.encryptor());
	}
	
	@Test
	public void testSetExecutor() throws Exception {
		
		Executor executor1 = ESAPI.executor();
		Assert.assertSame(executor1, ESAPI.setExecutor(executor1));
		
		Executor executor2 = new DefaultExecutor();
		Assert.assertSame(executor1, ESAPI.setExecutor(executor2));
		Assert.assertSame(executor2, ESAPI.executor());
	}
	
	@Test
	public void testSetHttpUtilities() throws Exception {
		
		HTTPUtilities httpUtilities1 = ESAPI.httpUtilities();
		Assert.assertSame(httpUtilities1, ESAPI.setHttpUtilities(httpUtilities1));
		
		HTTPUtilities httpUtilities2 = new DefaultHTTPUtilities();
		Assert.assertSame(httpUtilities1, ESAPI.setHttpUtilities(httpUtilities2));
		Assert.assertSame(httpUtilities2, ESAPI.httpUtilities());
	}
	
	@Test
	public void testSetIntrusionDetector() throws Exception {
		
		IntrusionDetector intrusionDetector1 = ESAPI.intrusionDetector();
		Assert.assertSame(intrusionDetector1, ESAPI.setIntrusionDetector(intrusionDetector1));
		
		IntrusionDetector intrusionDetector2 = new DefaultIntrusionDetector();
		Assert.assertSame(intrusionDetector1, ESAPI.setIntrusionDetector(intrusionDetector2));
		Assert.assertSame(intrusionDetector2, ESAPI.intrusionDetector());
	}
	
	@Test
	public void testSetRandomizer() throws Exception {
		
		Randomizer randomizer1 = ESAPI.randomizer();
		Assert.assertSame(randomizer1, ESAPI.setRandomizer(randomizer1));
		
		Randomizer randomizer2 = new DefaultRandomizer();
		Assert.assertSame(randomizer1, ESAPI.setRandomizer(randomizer2));
		Assert.assertSame(randomizer2, ESAPI.randomizer());
	}
	
	@Test
	public void testSetSecurityConfiguration() throws Exception {
		
		SecurityConfiguration securityConfiguration = ESAPI.securityConfiguration();
		Assert.assertSame(securityConfiguration, ESAPI.setSecurityConfiguration(securityConfiguration));
		
		try {
			ESAPI.setSecurityConfiguration(null);
			Assert.fail("Expected Exception not thrown.");
		}
		catch (NullPointerException npe) {
			Assert.assertNotNull(npe.getMessage());
		}
		
		Assert.assertSame(securityConfiguration, ESAPI.securityConfiguration());
	}
	
	@Test
	public void testSetValidator() throws Exception {
		
		Validator validator1 = ESAPI.validator();
		Assert.assertSame(validator1, ESAPI.setValidator(validator1));
		
		Validator validator2 = new DefaultValidator();
		Assert.assertSame(validator1, ESAPI.setValidator(validator2));
		Assert.assertSame(validator2, ESAPI.validator());
	}
	
	@Test
	public void testSetLogFactory() throws Exception {
		
		LogFactory logFactory1 = new JavaLogFactory();
		ESAPI.setLogFactory(logFactory1);
		
		LogFactory logFactory2 = new JavaLogFactory();
		Assert.assertSame(logFactory1, ESAPI.setLogFactory(logFactory2));
	}

}
