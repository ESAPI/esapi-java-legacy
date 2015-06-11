package org.owasp.esapi.configuration;


import org.junit.BeforeClass;
import org.junit.Test;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.errors.ConfigurationException;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;

import static junit.framework.Assert.*;

public class StandardEsapiPropertyLoaderTest {

    private static String filename;
    private static int priority;

    private StandardEsapiPropertyLoader testPropertyLoader;

    @BeforeClass
    public static void init() {
        filename = "src" + File.separator + "test" + File.separator + "resources" + File.separator +
                "esapi" + File.separator + "ESAPI-test.properties";
        priority = 1;
    }

    @Test
    public void testPropertiesLoaded() {
        // when
        try {
            testPropertyLoader = new StandardEsapiPropertyLoader(filename, priority);
        } catch (FileNotFoundException e) {
            fail(e.getMessage());
        }
        
        // then
        assertFalse(testPropertyLoader.properties.isEmpty());
    }

    @Test(expected = FileNotFoundException.class)
    public void testPropertiesFileNotFound() throws FileNotFoundException {
        // given
        String wrongFilename = "wrong_filename";
        testPropertyLoader = new StandardEsapiPropertyLoader(wrongFilename, priority);

        // when
        testPropertyLoader = new StandardEsapiPropertyLoader(filename, priority);

        // then expect exception
    }

    @Test
    public void testPriority() {
        int expectedValue = 1;
        try {
            testPropertyLoader = new StandardEsapiPropertyLoader(filename, priority);
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
            testPropertyLoader = new StandardEsapiPropertyLoader(filename, priority);
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
            testPropertyLoader = new StandardEsapiPropertyLoader(filename, priority);
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
            testPropertyLoader = new StandardEsapiPropertyLoader(filename, priority);
            StandardEsapiPropertyLoader otherPropertyLoader = new StandardEsapiPropertyLoader(filename, lowerPriority);
            int value = testPropertyLoader.compareTo(otherPropertyLoader);
            assertEquals(expectedValue, value);
        } catch (FileNotFoundException e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void testGetIntProp() {
        // given
        String propertyKey = "int_property";
        
        // when
        try {
            testPropertyLoader = new StandardEsapiPropertyLoader(filename, priority);
        } catch (FileNotFoundException e) {
            fail(e.getMessage());
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
            testPropertyLoader.getIntProp(propertyKey);
        } catch (FileNotFoundException e) {
            fail(e.getMessage());
        }

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
            
        } catch (FileNotFoundException e) {
            fail(e.getMessage());
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
            testPropertyLoader.getStringProp(propertyKey);
        } catch (FileNotFoundException e) {
            fail(e.getMessage());
        }

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
        } catch (FileNotFoundException e) {
            fail(e.getMessage());
        }
        boolean value = testPropertyLoader.getBooleanProp(propertyKey);
        
        // then
        assertEquals(expectedValue, value);
    }

    @Test(expected = ConfigurationException.class)
    public void testBooleanPropertyNotFound() throws ConfigurationException {
        // given
        String filename = "src" + File.separator + "test" + File.separator + "resources" + File.separator +
                "esapi" + File.separator + "ESAPI-test.properties";        int priority = 1;
        String propertyKey = "non-existing-key";
        
        // when
        try {
            testPropertyLoader = new StandardEsapiPropertyLoader(filename, priority);
            testPropertyLoader.getBooleanProp(propertyKey);
        } catch (FileNotFoundException e) {
            fail(e.getMessage());
        }

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
        } catch (FileNotFoundException e) {
            fail(e.getMessage());
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
            testPropertyLoader.getByteArrayProp(propertyKey);
        } catch (FileNotFoundException e) {
            fail(e.getMessage());
        }

        // then expect exception
    }

}
