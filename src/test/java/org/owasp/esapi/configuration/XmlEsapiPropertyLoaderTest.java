package org.owasp.esapi.configuration;

import org.junit.Before;
import org.junit.Test;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.configuration.consts.EsapiConfiguration;
import org.owasp.esapi.errors.ConfigurationException;

import java.io.File;
import java.io.IOException;

import static junit.framework.Assert.*;

public class XmlEsapiPropertyLoaderTest {

    private static String filename;
    private static int priority;

    private XmlEsapiPropertyLoader testPropertyLoader;

    @Before
    public void init() {
        System.setProperty(EsapiConfiguration.DEVTEAM_ESAPI_CFG.getConfigName(), "");
        System.setProperty(EsapiConfiguration.OPSTEAM_ESAPI_CFG.getConfigName(), "");
        filename = "src" + File.separator + "test" + File.separator + "resources" + File.separator +
                "esapi" + File.separator + "ESAPI-test.xml";
        priority = 1;
    }

    @Test
    public void testPropertiesLoaded() {
        // when
        try {
            testPropertyLoader = new XmlEsapiPropertyLoader(filename, priority);
        } catch ( IOException e ) {
            fail( e.getMessage() );
        }

        // then
        assertFalse(testPropertyLoader.properties.isEmpty());
    }

    @Test
    public void testInvalidPropertyFile() {
        // given - the file exists, but does not conform to the schema.
        String invalidFilename = "src" + File.separator + "test" + File.separator + "resources" + File.separator +
                "esapi" + File.separator + "ESAPI-test-invalid-content.xml";

        // when
        try {
            testPropertyLoader = new XmlEsapiPropertyLoader(invalidFilename, priority);
        } catch ( IOException iex ) {
            // iex.printStackTrace(System.err);
            fail("Caught unexpected IOException; exception was: " + iex);
        } catch ( ConfigurationException cex) {
            return;
        }

        fail("Failed to catch expected ConfigurationException for invalid property file name: " + invalidFilename);
    }

    @Test
    public void testPriority() {
        // given
        int expectedValue = 1;

        // when
        try {
            testPropertyLoader = new XmlEsapiPropertyLoader(filename, priority);
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
            testPropertyLoader = new XmlEsapiPropertyLoader(filename, priority);
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
            testPropertyLoader = new XmlEsapiPropertyLoader(filename, priority);
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
            testPropertyLoader = new XmlEsapiPropertyLoader(filename, priority);
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
        String key = "int_property";
        int expectedValue = 5;

        // when
        try {
            testPropertyLoader = new XmlEsapiPropertyLoader(filename, priority);
        } catch ( IOException e ) {
            fail( e.getMessage() );
        }
        int value = testPropertyLoader.getIntProp(key);

        // then
        assertEquals(expectedValue, value);
    }

    @Test(expected = ConfigurationException.class)
    public void testIntPropertyNotFound() throws ConfigurationException {
        // given
        String key = "non-existing-key";

        // when
        try {
            testPropertyLoader = new XmlEsapiPropertyLoader(filename, priority);
        } catch ( IOException e ) {
            fail( e.getMessage() );
        }
        testPropertyLoader.getIntProp(key);

        // then expect exception
    }

    @Test(expected = ConfigurationException.class)
    public void testIncorrectIntPropertyType() {
        // given
        String key = "invalid_int_property";

        // when
        try {
            testPropertyLoader = new XmlEsapiPropertyLoader(filename, priority);
        } catch ( IOException e ) {
            fail( e.getMessage() );
        }
        testPropertyLoader.getIntProp(key);

        // then expect exception
    }

    @Test
    public void testGetStringProp() {
        // given
        String key = "string_property";
        String expectedValue = "test_string_property";

        // when
        try {
            testPropertyLoader = new XmlEsapiPropertyLoader(filename, priority);
        } catch ( IOException e ) {
            fail( e.getMessage() );
        }
        String value = testPropertyLoader.getStringProp(key);

        // then
        assertEquals(expectedValue, value);
    }

    @Test(expected = ConfigurationException.class)
    public void testStringPropertyNotFound() throws ConfigurationException {
        // given
        String key = "non-existing-key";

        // when
        try {
            testPropertyLoader = new XmlEsapiPropertyLoader(filename, priority);
        } catch ( IOException e ) {
            fail( e.getMessage() );
        }
        testPropertyLoader.getStringProp(key);

        // then expect exception
    }

    @Test
    public void testGetBooleanProp() {
        // given
        String key = "boolean_property";
        boolean expectedValue = true;

        // when
        try {
            testPropertyLoader = new XmlEsapiPropertyLoader(filename, priority);
        } catch ( IOException e ) {
            fail( e.getMessage() );
        }
        boolean value = testPropertyLoader.getBooleanProp(key);

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
            testPropertyLoader = new XmlEsapiPropertyLoader(filename, priority);
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
            testPropertyLoader = new XmlEsapiPropertyLoader(filename, priority);
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
        String key = "non-existing-key";

        // when
        try {
            testPropertyLoader = new XmlEsapiPropertyLoader(filename, priority);
        } catch ( IOException e ) {
            fail( e.getMessage() );
        }
        testPropertyLoader.getBooleanProp(key);

        // then expect exception
    }

    @Test(expected = ConfigurationException.class)
    public void testIncorrectBooleanPropertyType() throws ConfigurationException {
        // given
        String key = "invalid_boolean_property";

        // when
        try {
            testPropertyLoader = new XmlEsapiPropertyLoader(filename, priority);
        } catch ( IOException e ) {
            fail( e.getMessage() );
        }
        testPropertyLoader.getBooleanProp(key);

        // then expect exception
    }

    @Test
    public void testGetByteArrayProp() {
        // given
        String key = "string_property";
        byte[] expectedValue = new byte[0];
        try {
            expectedValue = ESAPI.encoder().decodeFromBase64("test_string_property");
        } catch (IOException e) {
            fail(e.getMessage());
        }

        // when
        try {
            testPropertyLoader = new XmlEsapiPropertyLoader(filename, priority);
        } catch ( IOException e ) {
            fail( e.getMessage() );
        }
        byte[] value = testPropertyLoader.getByteArrayProp(key);

        // then
        assertEquals(expectedValue, value);
    }

    @Test(expected = ConfigurationException.class)
    public void testByteArrayPropertyNotFound() throws ConfigurationException {
        // given
        String key = "non-existing-key";

        // when
        try {
            testPropertyLoader = new XmlEsapiPropertyLoader(filename, priority);
        } catch ( IOException e ) {
            fail( e.getMessage() );
        }
        testPropertyLoader.getByteArrayProp(key);

        // then expect exception
    }

}
