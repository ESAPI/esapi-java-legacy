package org.owasp.esapi.configuration;

import org.junit.BeforeClass;
import org.junit.Test;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.errors.ConfigurationException;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertFalse;
import static junit.framework.Assert.fail;

public class XmlEsapiPropertyLoaderTest {

    private static String filename;
    private static int priority;

    private XmlEsapiPropertyLoader testPropertyLoader;

    @BeforeClass
    public static void init() {
        filename = "src" + File.separator + "test" + File.separator + "resources" + File.separator +
                "esapi" + File.separator + "ESAPI-test.xml";
        priority = 1;
    }

    @Test
    public void testPropertiesLoaded() {
        // when
        testPropertyLoader = new XmlEsapiPropertyLoader(filename, priority);

        // then
        assertFalse(testPropertyLoader.properties.isEmpty());
    }

    @Test
    public void testPriority() {
        // given
        int expectedValue = 1;

        // when
        testPropertyLoader = new XmlEsapiPropertyLoader(filename, priority);
        int value = testPropertyLoader.priority();

        // then
        assertEquals(expectedValue, value);
    }

    @Test
    public void testLoadersAreEqual() {
        // given
        int expectedValue = 0;

        // when
        testPropertyLoader = new XmlEsapiPropertyLoader(filename, priority);
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
        testPropertyLoader = new XmlEsapiPropertyLoader(filename, priority);
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
        testPropertyLoader = new XmlEsapiPropertyLoader(filename, priority);
        StandardEsapiPropertyLoader otherPropertyLoader = new StandardEsapiPropertyLoader(filename, lowerPriority);
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
        testPropertyLoader = new XmlEsapiPropertyLoader(filename, priority);
        int value = testPropertyLoader.getIntProp(key);

        // then
        assertEquals(expectedValue, value);
    }

    @Test(expected = ConfigurationException.class)
    public void testIntPropertyNotFound() throws ConfigurationException {
        // given
        String key = "non-existing-key";

        // when
        testPropertyLoader = new XmlEsapiPropertyLoader(filename, priority);
        testPropertyLoader.getIntProp(key);

        // then expect exception
    }

    @Test
    public void testGetStringProp() {
        // given
        String key = "string_property";
        String expectedValue = "test_string_property";

        // when
        testPropertyLoader = new XmlEsapiPropertyLoader(filename, priority);
        String value = testPropertyLoader.getStringProp(key);

        // then
        assertEquals(expectedValue, value);
    }

    @Test(expected = ConfigurationException.class)
    public void testStringPropertyNotFound() throws ConfigurationException {
        // given
        String key = "non-existing-key";

        // when
        testPropertyLoader = new XmlEsapiPropertyLoader(filename, priority);
        testPropertyLoader.getStringProp(key);

        // then expect exception
    }

    @Test
    public void testGetBooleanProp() {
        // given
        String key = "boolean_property";
        boolean expectedValue = true;

        // when
        testPropertyLoader = new XmlEsapiPropertyLoader(filename, priority);
        boolean value = testPropertyLoader.getBooleanProp(key);

        // then
        assertEquals(expectedValue, value);
    }

    @Test(expected = ConfigurationException.class)
    public void testBooleanPropertyNotFound() throws ConfigurationException {
        // given
        String key = "non-existing-key";

        // when
        testPropertyLoader = new XmlEsapiPropertyLoader(filename, priority);
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
        testPropertyLoader = new XmlEsapiPropertyLoader(filename, priority);
        byte[] value = testPropertyLoader.getByteArrayProp(key);

        // then
        assertEquals(expectedValue, value);
    }

    @Test(expected = ConfigurationException.class)
    public void testByteArrayPropertyNotFound() throws ConfigurationException {
        // given
        String key = "non-existing-key";

        // when
        testPropertyLoader = new XmlEsapiPropertyLoader(filename, priority);
        testPropertyLoader.getByteArrayProp(key);

        // then expect exception
    }

}
