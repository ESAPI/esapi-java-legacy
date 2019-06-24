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
        try {
            testPropertyLoader = new StandardEsapiPropertyLoader(filename, priority);
        } catch ( IOException e ) {
            fail( e.getMessage() );
        }

        // then
        assertFalse(testPropertyLoader.properties.isEmpty());
    }

    @Test
    public void testPriority() {
        // given
        int expectedValue = 1;

        // when
        try {
            testPropertyLoader = new StandardEsapiPropertyLoader(filename, priority);
        } catch ( IOException e ) {
            fail( e.getMessage() );
        }
        int value = testPropertyLoader.priority();

        // then
        assertEquals(expectedValue, value);
    }

    @Test
    public void testLoadersAreEqual() {
        // given
        int expectedValue = 0;
        StandardEsapiPropertyLoader otherPropertyLoader = null;

        // when
        try {
            testPropertyLoader = new StandardEsapiPropertyLoader(filename, priority);
            otherPropertyLoader = new StandardEsapiPropertyLoader(filename, priority);
        } catch ( IOException e ) {
            fail( e.getMessage() );
        }
        int value = testPropertyLoader.compareTo(otherPropertyLoader);

        // then
        assertEquals(expectedValue, value);
    }

    @Test
    public void testCompareWithOtherLoaderWithHigherPriority() {
        // given
        int expectedValue = -1;
        int higherPriority = 2;
        StandardEsapiPropertyLoader otherPropertyLoader = null;

        // when
        try {
            testPropertyLoader = new StandardEsapiPropertyLoader(filename, priority);
            otherPropertyLoader = new StandardEsapiPropertyLoader(filename, higherPriority);
        } catch ( IOException e ) {
            fail( e.getMessage() );
        }
        int value = testPropertyLoader.compareTo(otherPropertyLoader);

        // then
        assertEquals(expectedValue, value);
    }

    @Test
    public void testCompareWithOtherLoaderWithLowerPriority() {
        // given
        int expectedValue = 1;
        int lowerPriority = 0;
        StandardEsapiPropertyLoader otherPropertyLoader = null;

        // when
        try {
            testPropertyLoader = new StandardEsapiPropertyLoader(filename, priority);
            otherPropertyLoader = new StandardEsapiPropertyLoader(filename, lowerPriority);
        } catch ( IOException e ) {
            fail( e.getMessage() );
        }
        int value = testPropertyLoader.compareTo(otherPropertyLoader);

        // then
        assertEquals(expectedValue, value);
    }

    @Test
    public void testGetIntProp() {
        // given
        String propertyKey = "int_property";
        
        // when
        try {
            testPropertyLoader = new StandardEsapiPropertyLoader(filename, priority);
        } catch ( IOException e ) {
            fail( e.getMessage() );
        }
        int propertyValue = testPropertyLoader.getIntProp(propertyKey);

        // then
        assertEquals(5, propertyValue);
    }

    @Test(expected = ConfigurationException.class)
    public void testIntPropertyNotFound() throws ConfigurationException {
        // given
        String propertyKey = "non-existing-key";
        
        // when
        try {
            testPropertyLoader = new StandardEsapiPropertyLoader(filename, priority);
        } catch ( IOException e ) {
            fail( e.getMessage() );
        }
        testPropertyLoader.getIntProp(propertyKey);

        // then expect exception
    }

    @Test(expected = ConfigurationException.class)
    public void testIncorrectIntPropertyType() {
        // given
        String key = "invalid_int_property";

        // when
        try {
            testPropertyLoader = new StandardEsapiPropertyLoader(filename, priority);
        } catch ( IOException e ) {
            fail( e.getMessage() );
        }
        testPropertyLoader.getIntProp(key);

        // then expect exception
    }

    @Test
    public void testGetStringProp() {
        // given
        String propertyKey = "string_property";
        String expectedValue = "test_string_property";
        
        // when
        try {
            testPropertyLoader = new StandardEsapiPropertyLoader(filename, priority);
        } catch ( IOException e ) {
            fail( e.getMessage() );
        }
        String propertyValue = testPropertyLoader.getStringProp(propertyKey);
        
        // then
        assertEquals(expectedValue, propertyValue);
    }

    @Test(expected = ConfigurationException.class)
    public void testStringPropertyNotFound() throws ConfigurationException {
        // given
        String propertyKey = "non-existing-key";
        
        // when
        try {
            testPropertyLoader = new StandardEsapiPropertyLoader(filename, priority);
        } catch ( IOException e ) {
            fail( e.getMessage() );
        }
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
        try {
            testPropertyLoader = new StandardEsapiPropertyLoader(filename, priority);
        } catch ( IOException e ) {
            fail( e.getMessage() );
        }
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
        try {
            testPropertyLoader = new StandardEsapiPropertyLoader(filename, priority);
        } catch ( IOException e ) {
            fail( e.getMessage() );
        }
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
        try {
            testPropertyLoader = new StandardEsapiPropertyLoader(filename, priority);
        } catch ( IOException e ) {
            fail( e.getMessage() );
        }
        boolean value = testPropertyLoader.getBooleanProp(key);

        // then
        assertEquals(expectedValue, value);
    }

    @Test(expected = ConfigurationException.class)
    public void testBooleanPropertyNotFound() throws ConfigurationException {
        // given
        String filename = "src" + File.separator + "test" + File.separator + "resources" + File.separator +
                "esapi" + File.separator + "ESAPI-test.properties";
        int priority = 1;
        String propertyKey = "non-existing-key";
        
        // when
        try {
            testPropertyLoader = new StandardEsapiPropertyLoader(filename, priority);
        } catch ( IOException e ) {
            fail( e.getMessage() );
        }
        testPropertyLoader.getBooleanProp(propertyKey);

        // then expect exception
    }

    @Test(expected = ConfigurationException.class)
    public void testIncorrectBooleanPropertyType() throws ConfigurationException {
        // given
        String key = "invalid_boolean_property";

        // when
        try {
            testPropertyLoader = new StandardEsapiPropertyLoader(filename, priority);
        } catch ( IOException e ) {
            fail( e.getMessage() );
        }
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
        try {
            testPropertyLoader = new StandardEsapiPropertyLoader(filename, priority);
        } catch ( IOException e ) {
            fail( e.getMessage() );
        }
        byte[] value = testPropertyLoader.getByteArrayProp(propertyKey);
        
        // then
        assertEquals(expectedValue, value);
    }

    @Test(expected = ConfigurationException.class)
    public void testByteArrayPropertyNotFound() throws ConfigurationException {
        // given
        String filename = "src" + File.separator + "test" + File.separator + "resources" + File.separator +
                "esapi" + File.separator + "ESAPI-test.properties";        int priority = 1;
        String propertyKey = "non-existing-key";
        
        // when
        try {
            testPropertyLoader = new StandardEsapiPropertyLoader(filename, priority);
        } catch ( IOException e ) {
            fail( e.getMessage() );
        }

        testPropertyLoader.getByteArrayProp(propertyKey);

        // then expect exception
    }

}
