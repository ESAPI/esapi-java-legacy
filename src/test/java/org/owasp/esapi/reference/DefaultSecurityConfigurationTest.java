package org.owasp.esapi.reference;

import junit.framework.Assert;

import org.junit.Test;

public class DefaultSecurityConfigurationTest {

	@Test
	public void testGetApplicationName() {
		final String expected = "ESAPI_UnitTests";
		java.util.Properties properties = new java.util.Properties();
		properties.setProperty("Logger.ApplicationName", expected);
		
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(properties);
		Assert.assertEquals(expected, secConf.getApplicationName());
	}
	
	@Test
	public void testGetLogImplementation() {
		final String expected = "TestLogger";
		java.util.Properties properties = new java.util.Properties();
		properties.setProperty("ESAPI.Logger", expected);
		
		DefaultSecurityConfiguration secConf = new DefaultSecurityConfiguration(properties);
		Assert.assertEquals(expected, secConf.getLogImplementation());
	}
	
}
