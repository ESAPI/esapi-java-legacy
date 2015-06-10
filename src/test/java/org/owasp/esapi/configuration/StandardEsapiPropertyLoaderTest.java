package org.owasp.esapi.configuration;

import static junit.framework.Assert.*;
import org.junit.Test;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.errors.ConfigurationException;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;

public class StandardEsapiPropertyLoaderTest {

    private StandardEsapiPropertyLoader testPropertyLoader;

    @Test
    public void testPropertiesLoaded() {
        String filename = "src" + File.separator + "test" + File.separator + "resources" + File.separator +
                "esapi" + File.separator + "ESAPI-test.properties";
        int priority = 1;
        try {
            testPropertyLoader = new StandardEsapiPropertyLoader(filename, priority);
        } catch (FileNotFoundException e) {
            fail(e.getMessage());
        }

        assertFalse(testPropertyLoader.properties.isEmpty());
    }

    @Test(expected = FileNotFoundException.class)
    public void testPropertiesFileNotFound() throws FileNotFoundException{
        String filename = "fail-src" + File.separator + "test" + File.separator + "resources" + File.separator +
                "esapi" + File.separator + "ESAPI-test.properties";
        int priority = 1;
        testPropertyLoader = new StandardEsapiPropertyLoader(filename, priority);
    }

    @Test
    public void testGetIntProp() {
        String filename = "src" + File.separator + "test" + File.separator + "resources" + File.separator +
                "esapi" + File.separator + "ESAPI-test.properties";
        int priority = 1;
        String key = "int_property";
        int expectedValue = 5;
        try {
            testPropertyLoader = new StandardEsapiPropertyLoader(filename, priority);
            int value = testPropertyLoader.getIntProp(key);
            assertEquals(expectedValue, value);
        } catch (FileNotFoundException e) {
            fail(e.getMessage());
        }
    }

    @Test(expected = ConfigurationException.class)
    public void testIntPropertyNotFound() throws ConfigurationException {
        String filename = "src" + File.separator + "test" + File.separator + "resources" + File.separator +
                "esapi" + File.separator + "ESAPI-test.properties";
        int priority = 1;
        String key = "non-existing-key";
        try {
            testPropertyLoader = new StandardEsapiPropertyLoader(filename, priority);
            testPropertyLoader.getIntProp(key);
        } catch (FileNotFoundException e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void testGetStringProp() {
        String filename = "src" + File.separator + "test" + File.separator + "resources" + File.separator +
                "esapi" + File.separator + "ESAPI-test.properties";
        int priority = 1;
        String key = "string_property";
        String expectedValue = "test_string_property";
        try {
            testPropertyLoader = new StandardEsapiPropertyLoader(filename, priority);
            String value = testPropertyLoader.getStringProp(key);
            assertEquals(expectedValue, value);
        } catch (FileNotFoundException e) {
            fail(e.getMessage());
        }
    }

    @Test(expected = ConfigurationException.class)
    public void testStringPropertyNotFound() throws ConfigurationException {
        String filename = "src" + File.separator + "test" + File.separator + "resources" + File.separator +
                "esapi" + File.separator + "ESAPI-test.properties";        int priority = 1;
        String key = "non-existing-key";
        try {
            testPropertyLoader = new StandardEsapiPropertyLoader(filename, priority);
            testPropertyLoader.getStringProp(key);
        } catch (FileNotFoundException e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void testGetBooleanProp() {
        String filename = "src" + File.separator + "test" + File.separator + "resources" + File.separator +
                "esapi" + File.separator + "ESAPI-test.properties";
        int priority = 1;
        String key = "boolean_property";
        boolean expectedValue = true;
        try {
            testPropertyLoader = new StandardEsapiPropertyLoader(filename, priority);
            boolean value = testPropertyLoader.getBooleanProp(key);
            assertEquals(expectedValue, value);
        } catch (FileNotFoundException e) {
            fail(e.getMessage());
        }
    }

    @Test(expected = ConfigurationException.class)
    public void testBooleanPropertyNotFound() throws ConfigurationException {
        String filename = "src" + File.separator + "test" + File.separator + "resources" + File.separator +
                "esapi" + File.separator + "ESAPI-test.properties";        int priority = 1;
        String key = "non-existing-key";
        try {
            testPropertyLoader = new StandardEsapiPropertyLoader(filename, priority);
            testPropertyLoader.getBooleanProp(key);
        } catch (FileNotFoundException e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void testGetByteArrayProp() {
        String filename = "src" + File.separator + "test" + File.separator + "resources" + File.separator +
                "esapi" + File.separator + "ESAPI-test.properties";
        int priority = 1;
        String key = "string_property";
        byte[] expectedValue = new byte[0];
        try {
            expectedValue = ESAPI.encoder().decodeFromBase64("test_string_property");
        } catch (IOException e) {
            fail(e.getMessage());
        }
        try {
            testPropertyLoader = new StandardEsapiPropertyLoader(filename, priority);
            byte[] value = testPropertyLoader.getByteArrayProp(key);
            assertEquals(expectedValue, value);
        } catch (FileNotFoundException e) {
            fail(e.getMessage());
        }
    }

    @Test(expected = ConfigurationException.class)
    public void testByteArrayPropertyNotFound() throws ConfigurationException {
        String filename = "src" + File.separator + "test" + File.separator + "resources" + File.separator +
                "esapi" + File.separator + "ESAPI-test.properties";        int priority = 1;
        String key = "non-existing-key";
        try {
            testPropertyLoader = new StandardEsapiPropertyLoader(filename, priority);
            testPropertyLoader.getByteArrayProp(key);
        } catch (FileNotFoundException e) {
            fail(e.getMessage());
        }
    }

}
