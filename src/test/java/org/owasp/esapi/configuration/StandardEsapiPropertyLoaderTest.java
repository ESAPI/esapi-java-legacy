package org.owasp.esapi.configuration;


import org.junit.Before;
import org.junit.Test;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.configuration.consts.EsapiConfiguration;
import org.owasp.esapi.errors.ConfigurationException;

import java.io.File;
import java.io.IOException;

import static junit.framework.Assert.*;

public class StandardEsapiPropertyLoaderTest {

    private static String filename;
    private static int priority;

    private StandardEsapiPropertyLoader testPropertyLoader;

    @Before
    public void init() {
        System.setProperty(EsapiConfiguration.DEVTEAM_ESAPI_CFG.getConfigName(), "");
        System.setProperty(EsapiConfiguration.OPSTEAM_ESAPI_CFG.getConfigName(), "");
        filename = "src" + File.separator + "test" + File.separator + "resources" + File.separator +
                "esapi" + File.separator + "ESAPI-test.properties";
        priority = 1;
    }

    @Test
    public void testPropertiesLoaded() {
        // when
        testPropertyLoader = new StandardEsapiPropertyLoader(filename, priority);
        
        // then
        assertFalse(testPropertyLoader.properties.isEmpty());
    }

    @Test
    public void testPriority() {
        // given
        int expectedValue = 1;

        // when
        testPropertyLoader = new StandardEsapiPropertyLoader(filename, priority);
        int value = testPropertyLoader.priority();

        // then
        assertEquals(expectedValue, value);
    }

    @Test
    public void testLoadersAreEqual() {
        // given
        int expectedValue = 0;

        // when
        testPropertyLoader = new StandardEsapiPropertyLoader(filename, priority);
        StandardEsapiPropertyLoader otherPropertyLoader = new StandardEsapiPropertyLoader(filename, priority);
        int value = testPropertyLoader.compareTo(otherPropertyLoader);

        // then
        assertEquals(expectedValue, value);
    }

    @Test
    public void testCompareWithOtherLoaderWithHigherPriority() {
        // given
        int expectedValue = -1;
        int higherPriority = 2;

        // when
        testPropertyLoader = new StandardEsapiPropertyLoader(filename, priority);
        StandardEsapiPropertyLoader otherPropertyLoader = new StandardEsapiPropertyLoader(filename, higherPriority);
        int value = testPropertyLoader.compareTo(otherPropertyLoader);

        // then
        assertEquals(expectedValue, value);
    }

    @Test
    public void testCompareWithOtherLoaderWithLowerPriority() {
        // given
        int expectedValue = 1;
        int lowerPriority = 0;

        // when
        testPropertyLoader = new StandardEsapiPropertyLoader(filename, priority);
        StandardEsapiPropertyLoader otherPropertyLoader = new StandardEsapiPropertyLoader(filename, lowerPriority);
        int value = testPropertyLoader.compareTo(otherPropertyLoader);

        // then
        assertEquals(expectedValue, value);
    }

    @Test
    public void testGetIntProp() {
        // given
        String propertyKey = "int_property";
        
        // when
        testPropertyLoader = new StandardEsapiPropertyLoader(filename, priority);
        int propertyValue = testPropertyLoader.getIntProp(propertyKey);

        // then
        assertEquals(5, propertyValue);
    }

    @Test(expected = ConfigurationException.class)
    public void testIntPropertyNotFound() throws ConfigurationException {
        // given
        String propertyKey = "non-existing-key";
        
        // when
        testPropertyLoader = new StandardEsapiPropertyLoader(filename, priority);
        testPropertyLoader.getIntProp(propertyKey);

        // then expect exception
    }

    @Test(expected = ConfigurationException.class)
    public void testIncorrectIntPropertyType() {
        // given
        String key = "invalid_int_property";

        // when
        testPropertyLoader = new StandardEsapiPropertyLoader(filename, priority);
        testPropertyLoader.getIntProp(key);

        // then expect exception
    }

    @Test
    public void testGetStringProp() {
        // given
        String propertyKey = "string_property";
        String expectedValue = "test_string_property";
        
        // when
        testPropertyLoader = new StandardEsapiPropertyLoader(filename, priority);
        String propertyValue = testPropertyLoader.getStringProp(propertyKey);
        
        // then
        assertEquals(expectedValue, propertyValue);
    }

    @Test(expected = ConfigurationException.class)
    public void testStringPropertyNotFound() throws ConfigurationException {
        // given
        String propertyKey = "non-existing-key";
        
        // when
        testPropertyLoader = new StandardEsapiPropertyLoader(filename, priority);
        testPropertyLoader.getStringProp(propertyKey);

        // then expect exception
    }

    @Test
    public void testGetBooleanProp() {
        // given
        String filename = "src" + File.separator + "test" + File.separator + "resources" + File.separator +
                "esapi" + File.separator + "ESAPI-test.properties";
        int priority = 1;
        String propertyKey = "boolean_property";
        boolean expectedValue = true;
        
        // when
        testPropertyLoader = new StandardEsapiPropertyLoader(filename, priority);
        boolean value = testPropertyLoader.getBooleanProp(propertyKey);
        
        // then
        assertEquals(expectedValue, value);
    }

    @Test
    public void testGetBooleanYesProperty() {
        // given
        String key = "boolean_yes_property";
        boolean expectedValue = true;

        // when
        testPropertyLoader = new StandardEsapiPropertyLoader(filename, priority);
        boolean value = testPropertyLoader.getBooleanProp(key);

        // then
        assertEquals(expectedValue, value);
    }

    @Test
    public void testGetBooleanNoProperty() {
        // given
        String key = "boolean_no_property";
        boolean expectedValue = false;

        // when
        testPropertyLoader = new StandardEsapiPropertyLoader(filename, priority);
        boolean value = testPropertyLoader.getBooleanProp(key);

        // then
        assertEquals(expectedValue, value);
    }

    @Test(expected = ConfigurationException.class)
    public void testBooleanPropertyNotFound() throws ConfigurationException {
        // given
        String filename = "src" + File.separator + "test" + File.separator + "src/main/resources" + File.separator +
                "esapi" + File.separator + "ESAPI-test.properties";        int priority = 1;
        String propertyKey = "non-existing-key";
        
        // when
        testPropertyLoader = new StandardEsapiPropertyLoader(filename, priority);
        testPropertyLoader.getBooleanProp(propertyKey);

        // then expect exception
    }

    @Test(expected = ConfigurationException.class)
    public void testIncorrectBooleanPropertyType() throws ConfigurationException {
        // given
        String key = "invalid_boolean_property";

        // when
        testPropertyLoader = new StandardEsapiPropertyLoader(filename, priority);
        testPropertyLoader.getBooleanProp(key);

        // then expect exception
    }

    @Test
    public void testGetByteArrayProp() {
        // given
        String filename = "src" + File.separator + "test" + File.separator + "resources" + File.separator +
                "esapi" + File.separator + "ESAPI-test.properties";
        int priority = 1;
        String propertyKey = "string_property";
        
        byte[] expectedValue = new byte[0];
        try {
            expectedValue = ESAPI.encoder().decodeFromBase64("test_string_property");
        } catch (IOException e) {
            fail(e.getMessage());
        }
        
        // when
        testPropertyLoader = new StandardEsapiPropertyLoader(filename, priority);
        byte[] value = testPropertyLoader.getByteArrayProp(propertyKey);
        
        // then
        assertEquals(expectedValue, value);
    }

    @Test(expected = ConfigurationException.class)
    public void testByteArrayPropertyNotFound() throws ConfigurationException {
        // given
        String filename = "src" + File.separator + "test" + File.separator + "src/main/resources" + File.separator +
                "esapi" + File.separator + "ESAPI-test.properties";        int priority = 1;
        String propertyKey = "non-existing-key";
        
        // when
        testPropertyLoader = new StandardEsapiPropertyLoader(filename, priority);
        testPropertyLoader.getByteArrayProp(propertyKey);

        // then expect exception
    }

}
