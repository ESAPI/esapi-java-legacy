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
        try {
            testPropertyLoader = new XmlEsapiPropertyLoader(filename, priority);
        } catch (FileNotFoundException e) {
            fail(e.getMessage());
        }
        assertFalse(testPropertyLoader.properties.isEmpty());
    }

    @Test(expected = FileNotFoundException.class)
    public void testPropertiesFileNotFound() throws FileNotFoundException{
        String wrongFilename = "wrong_name";
        testPropertyLoader = new XmlEsapiPropertyLoader(wrongFilename, priority);
    }

    @Test
    public void testPriority() {
        int expectedValue = 1;
        try {
            testPropertyLoader = new XmlEsapiPropertyLoader(filename, priority);
            int value = testPropertyLoader.priority();
            assertEquals(expectedValue, value);
        } catch (FileNotFoundException e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void testLoadersAreEqual() {
        int expectedValue = 0;
        try {
            testPropertyLoader = new XmlEsapiPropertyLoader(filename, priority);
            StandardEsapiPropertyLoader otherPropertyLoader = new StandardEsapiPropertyLoader(filename, priority);
            int value = testPropertyLoader.compareTo(otherPropertyLoader);
            assertEquals(expectedValue, value);
        } catch (FileNotFoundException e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void testCompareWithOtherLoaderWithHigherPriority() {
        int expectedValue = -1;
        int higherPriority = 2;
        try {
            testPropertyLoader = new XmlEsapiPropertyLoader(filename, priority);
            StandardEsapiPropertyLoader otherPropertyLoader = new StandardEsapiPropertyLoader(filename, higherPriority);
            int value = testPropertyLoader.compareTo(otherPropertyLoader);
            assertEquals(expectedValue, value);
        } catch (FileNotFoundException e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void testCompareWithOtherLoaderWithLowerPriority() {
        int expectedValue = 1;
        int lowerPriority = 0;
        try {
            testPropertyLoader = new XmlEsapiPropertyLoader(filename, priority);
            StandardEsapiPropertyLoader otherPropertyLoader = new StandardEsapiPropertyLoader(filename, lowerPriority);
            int value = testPropertyLoader.compareTo(otherPropertyLoader);
            assertEquals(expectedValue, value);
        } catch (FileNotFoundException e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void testGetIntProp() {
        String key = "int_property";
        int expectedValue = 5;
        try {
            testPropertyLoader = new XmlEsapiPropertyLoader(filename, priority);
            int value = testPropertyLoader.getIntProp(key);
            assertEquals(expectedValue, value);
        } catch (FileNotFoundException e) {
            fail(e.getMessage());
        }
    }

    @Test(expected = ConfigurationException.class)
    public void testIntPropertyNotFound() throws ConfigurationException {
        String key = "non-existing-key";
        try {
            testPropertyLoader = new XmlEsapiPropertyLoader(filename, priority);
            testPropertyLoader.getIntProp(key);
        } catch (FileNotFoundException e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void testGetStringProp() {
        String key = "string_property";
        String expectedValue = "test_string_property";
        try {
            testPropertyLoader = new XmlEsapiPropertyLoader(filename, priority);
            String value = testPropertyLoader.getStringProp(key);
            assertEquals(expectedValue, value);
        } catch (FileNotFoundException e) {
            fail(e.getMessage());
        }
    }

    @Test(expected = ConfigurationException.class)
    public void testStringPropertyNotFound() throws ConfigurationException {
        String key = "non-existing-key";
        try {
            testPropertyLoader = new XmlEsapiPropertyLoader(filename, priority);
            testPropertyLoader.getStringProp(key);
        } catch (FileNotFoundException e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void testGetBooleanProp() {
        String key = "boolean_property";
        boolean expectedValue = true;
        try {
            testPropertyLoader = new XmlEsapiPropertyLoader(filename, priority);
            boolean value = testPropertyLoader.getBooleanProp(key);
            assertEquals(expectedValue, value);
        } catch (FileNotFoundException e) {
            fail(e.getMessage());
        }
    }

    @Test(expected = ConfigurationException.class)
    public void testBooleanPropertyNotFound() throws ConfigurationException {
        String key = "non-existing-key";
        try {
            testPropertyLoader = new XmlEsapiPropertyLoader(filename, priority);
            testPropertyLoader.getBooleanProp(key);
        } catch (FileNotFoundException e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void testGetByteArrayProp() {
        String key = "string_property";
        byte[] expectedValue = new byte[0];
        try {
            expectedValue = ESAPI.encoder().decodeFromBase64("test_string_property");
        } catch (IOException e) {
            fail(e.getMessage());
        }
        try {
            testPropertyLoader = new XmlEsapiPropertyLoader(filename, priority);
            byte[] value = testPropertyLoader.getByteArrayProp(key);
            assertEquals(expectedValue, value);
        } catch (FileNotFoundException e) {
            fail(e.getMessage());
        }
    }

    @Test(expected = ConfigurationException.class)
    public void testByteArrayPropertyNotFound() throws ConfigurationException {
        String key = "non-existing-key";
        try {
            testPropertyLoader = new XmlEsapiPropertyLoader(filename, priority);
            testPropertyLoader.getByteArrayProp(key);
        } catch (FileNotFoundException e) {
            fail(e.getMessage());
        }
    }

}
