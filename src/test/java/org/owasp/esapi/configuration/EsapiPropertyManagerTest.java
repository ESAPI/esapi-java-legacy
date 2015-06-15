package org.owasp.esapi.configuration;

import org.junit.BeforeClass;
import org.junit.Test;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.errors.ConfigurationException;

import java.io.File;
import java.io.IOException;

import static junit.framework.Assert.*;

public class EsapiPropertyManagerTest {

    private static String propFilename1;
    private static String propFilename2;
    private static String xmlFilename1;
    private static String xmlFilename2;

    private EsapiPropertyManager testPropertyManager;

    @BeforeClass
    public static void init() {
        propFilename1 = "src" + File.separator + "test" + File.separator + "resources" + File.separator +
                "esapi" + File.separator + "ESAPI-test.properties";
        propFilename2 = "src" + File.separator + "test" + File.separator + "resources" + File.separator +
                "esapi" + File.separator + "ESAPI-test-2.properties";
        xmlFilename1 = "src" + File.separator + "test" + File.separator + "resources" + File.separator +
                "esapi" + File.separator + "ESAPI-test.xml";
        xmlFilename2 = "src" + File.separator + "test" + File.separator + "resources" + File.separator +
                "esapi" + File.separator + "ESAPI-test-2.xml";
    }

    @Test
    public void testPropertyManagerInitialized() {
        // when
        testPropertyManager = new EsapiPropertyManager();

        // then
        assertNotNull(testPropertyManager.loaders);
        assertNotSame(0, testPropertyManager.loaders.size());
    }

    @Test
    public void testStringPropFoundInLoader() {
        // given
        String propertyKey = "string_property";
        String expectedPropertyValue = "test_string_property";

        // when
        testPropertyManager = new EsapiPropertyManager();
        testPropertyManager.loaders.clear();
        testPropertyManager.loaders.add(new StandardEsapiPropertyLoader(propFilename1, 1));
        String propertyValue = testPropertyManager.getStringProp(propertyKey);

        // then
        assertEquals(expectedPropertyValue, propertyValue);
    }

    @Test
    public void testStringPropertyLoadedFromFileWithHigherPriority() {
        // given
        String propertyKey = "string_property";
        String expectedValue = "test_string_property_2";

        // when
        testPropertyManager = new EsapiPropertyManager();
        testPropertyManager.loaders.clear();
        testPropertyManager.loaders.add(new StandardEsapiPropertyLoader(propFilename1, 2));
        testPropertyManager.loaders.add(new XmlEsapiPropertyLoader(xmlFilename2, 1));
        String propertyValue = testPropertyManager.getStringProp(propertyKey);

        // then
        assertEquals(expectedValue, propertyValue);
    }

    @Test
    public void testStringPropertyLoadedFromPropFileWithHigherPriority() {
        // given
        String propertyKey = "string_property";
        String expectedValue = "test_string_property_2";

        // when
        testPropertyManager = new EsapiPropertyManager();
        testPropertyManager.loaders.clear();
        testPropertyManager.loaders.add(new StandardEsapiPropertyLoader(propFilename1, 2));
        testPropertyManager.loaders.add(new StandardEsapiPropertyLoader(propFilename2, 1));
        String propertyValue = testPropertyManager.getStringProp(propertyKey);

        // then
        assertEquals(expectedValue, propertyValue);
    }

    @Test
    public void testStringPropertyLoadedFromXmlFileWithHigherPriority() {
        // given
        String propertyKey = "string_property";
        String expectedValue = "test_string_property_2";

        // when
        testPropertyManager = new EsapiPropertyManager();
        testPropertyManager.loaders.clear();
        testPropertyManager.loaders.add(new XmlEsapiPropertyLoader(xmlFilename1, 2));
        testPropertyManager.loaders.add(new XmlEsapiPropertyLoader(xmlFilename2, 1));
        String propertyValue = testPropertyManager.getStringProp(propertyKey);

        // then
        assertEquals(expectedValue, propertyValue);
    }

    @Test
    public void testStringPropFoundInDefaultConfiguration() {
        // given
        String propertyKey = "Encryptor.ChooseIVMethod";    // property from ESAPI.properties in test res dir

        // when
        testPropertyManager = new EsapiPropertyManager();
//        testPropertyManager.loaders.clear();
        String propertyValue = testPropertyManager.getStringProp("Encryptor.ChooseIVMethod");

        // then
        assertNotNull(propertyValue);
    }

    @Test(expected = ConfigurationException.class)
    public void testStringPropertyNotFoundByLoaderAndThrowException() {
        // given
        String propertyKey = "non.existing.property";

        // when
        testPropertyManager = new EsapiPropertyManager();
        testPropertyManager.loaders.clear();
        testPropertyManager.loaders.add(new StandardEsapiPropertyLoader(propFilename1, 1));
        testPropertyManager.getStringProp(propertyKey);

        // then expect exception
    }

    @Test
    public void testIntPropFoundInLoader() {
        // given
        String propertyKey = "int_property";
        int expectedPropertyValue = 5;

        // when
        testPropertyManager = new EsapiPropertyManager();
        testPropertyManager.loaders.clear();
        testPropertyManager.loaders.add(new StandardEsapiPropertyLoader(propFilename1, 1));
        int propertyValue = testPropertyManager.getIntProp(propertyKey);

        // then
        assertEquals(expectedPropertyValue, propertyValue);
    }

    @Test
    public void testIntPropertyLoadedFromFileWithHigherPriority() {
        // given
        String propertyKey = "int_property";
        int expectedValue = 52;

        // when
        testPropertyManager = new EsapiPropertyManager();
        testPropertyManager.loaders.clear();
        testPropertyManager.loaders.add(new StandardEsapiPropertyLoader(propFilename1, 2));
        testPropertyManager.loaders.add(new XmlEsapiPropertyLoader(xmlFilename2, 1));
        int propertyValue = testPropertyManager.getIntProp(propertyKey);

        // then
        assertEquals(expectedValue, propertyValue);
    }

    @Test
    public void testIntPropertyLoadedFromPropFileWithHigherPriority() {
        // given
        String propertyKey = "int_property";
        int expectedValue = 52;    // value from ESAPI-test-2.properties file

        // when
        testPropertyManager = new EsapiPropertyManager();
        testPropertyManager.loaders.clear();
        testPropertyManager.loaders.add(new StandardEsapiPropertyLoader(propFilename1, 2));
        testPropertyManager.loaders.add(new StandardEsapiPropertyLoader(propFilename2, 1));
        int propertyValue = testPropertyManager.getIntProp(propertyKey);

        // then
        assertEquals(expectedValue, propertyValue);
    }

    @Test
    public void testIntPropertyLoadedFromXmlFileWithHigherPriority() {
        // given
        String propertyKey = "int_property";
        int expectedValue = 52;

        // when
        testPropertyManager = new EsapiPropertyManager();
        testPropertyManager.loaders.clear();
        testPropertyManager.loaders.add(new XmlEsapiPropertyLoader(xmlFilename1, 2));
        testPropertyManager.loaders.add(new XmlEsapiPropertyLoader(xmlFilename2, 1));
        int propertyValue = testPropertyManager.getIntProp(propertyKey);

        // then
        assertEquals(expectedValue, propertyValue);
    }

    @Test
    public void testIntPropFoundInDefaultConfiguration() {
        // given
        String propertyKey = "Encryptor.DigitalSignatureKeyLength";    // property from ESAPI.properties in test res dir

        // when
        testPropertyManager = new EsapiPropertyManager();
        int propertyValue = testPropertyManager.getIntProp(propertyKey);

        // then
        assertNotNull(propertyValue);
    }

    @Test(expected = ConfigurationException.class)
    public void testIntPropertyNotFoundByLoaderAndThrowException() {
        // given
        String propertyKey = "non.existing.property";

        // when
        testPropertyManager = new EsapiPropertyManager();
        testPropertyManager.loaders.clear();
        testPropertyManager.loaders.add(new StandardEsapiPropertyLoader(propFilename1, 1));
        testPropertyManager.getIntProp(propertyKey);

        // then expect exception
    }

    @Test
    public void testBooleanPropFoundInLoader() {
        // given
        String propertyKey = "boolean_property";
        boolean expectedPropertyValue = true;

        // when
        testPropertyManager = new EsapiPropertyManager();
        testPropertyManager.loaders.clear();
        testPropertyManager.loaders.add(new StandardEsapiPropertyLoader(propFilename1, 1));
        boolean propertyValue = testPropertyManager.getBooleanProp(propertyKey);

        // then
        assertEquals(expectedPropertyValue, propertyValue);
    }

    @Test
    public void testBooleanPropFoundInDefaultConfiguration() {
        // given
        String propertyKey = "Encryptor.CipherText.useMAC";    // property from ESAPI.properties in test res dir

        // when
        testPropertyManager = new EsapiPropertyManager();
        boolean propertyValue = testPropertyManager.getBooleanProp(propertyKey);

        // then
        assertNotNull(propertyValue);
    }

    @Test(expected = ConfigurationException.class)
    public void testBooleanPropertyNotFoundByLoaderAndThrowException() {
        // given
        String propertyKey = "non.existing.property";

        // when
        testPropertyManager = new EsapiPropertyManager();
        testPropertyManager.loaders.clear();
        testPropertyManager.loaders.add(new StandardEsapiPropertyLoader(propFilename1, 1));
        testPropertyManager.getBooleanProp(propertyKey);

        // then expect exception
    }

    @Test
    public void testByteArrayPropFoundInLoader() {
        // given
        String propertyKey = "string_property";
        byte[] expectedValue = new byte[0];
        try {
            expectedValue = ESAPI.encoder().decodeFromBase64("test_string_property");
        } catch (IOException e) {
            fail(e.getMessage());
        }

        // when
        testPropertyManager = new EsapiPropertyManager();
        testPropertyManager.loaders.clear();
        testPropertyManager.loaders.add(new StandardEsapiPropertyLoader(propFilename1, 1));
        byte[] propertyValue = testPropertyManager.getByteArrayProp(propertyKey);

        // then
        assertEquals(expectedValue, propertyValue);
    }

    @Test
    public void testByteArrayPropertyLoadedFromFileWithHigherPriority() {
        // given
        String propertyKey = "string_property";
        byte[] expectedValue = new byte[0];
        try {
            expectedValue = ESAPI.encoder().decodeFromBase64("test_string_property_2");
        } catch (IOException e) {
            fail(e.getMessage());
        }

        // when
        testPropertyManager = new EsapiPropertyManager();
        testPropertyManager.loaders.clear();
        testPropertyManager.loaders.add(new StandardEsapiPropertyLoader(propFilename1, 2));
        testPropertyManager.loaders.add(new XmlEsapiPropertyLoader(xmlFilename2, 1));
        byte[] propertyValue = testPropertyManager.getByteArrayProp(propertyKey);

        // then
        assertEquals(expectedValue, propertyValue);
    }

    @Test
    public void testByteArrayPropertyLoadedFromPropFileWithHigherPriority() {
        // given
        String propertyKey = "string_property";
        byte[] expectedValue = new byte[0];
        try {
            expectedValue = ESAPI.encoder().decodeFromBase64("test_string_property_2");
        } catch (IOException e) {
            fail(e.getMessage());
        }

        // when
        testPropertyManager = new EsapiPropertyManager();
        testPropertyManager.loaders.clear();
        testPropertyManager.loaders.add(new StandardEsapiPropertyLoader(propFilename1, 2));
        testPropertyManager.loaders.add(new StandardEsapiPropertyLoader(propFilename2, 1));
        byte[] propertyValue = testPropertyManager.getByteArrayProp(propertyKey);

        // then
        assertEquals(expectedValue, propertyValue);
    }

    @Test
    public void testByteArrayPropertyLoadedFromXmlFileWithHigherPriority() {
        // given
        String propertyKey = "string_property";
        byte[] expectedValue = new byte[0];
        try {
            expectedValue = ESAPI.encoder().decodeFromBase64("test_string_property_2");
        } catch (IOException e) {
            fail(e.getMessage());
        }

        // when
        testPropertyManager = new EsapiPropertyManager();
        testPropertyManager.loaders.clear();
        testPropertyManager.loaders.add(new XmlEsapiPropertyLoader(xmlFilename1, 2));
        testPropertyManager.loaders.add(new XmlEsapiPropertyLoader(xmlFilename2, 1));
        byte[] propertyValue = testPropertyManager.getByteArrayProp(propertyKey);

        // then
        assertEquals(expectedValue, propertyValue);
    }

    @Test
    public void testByteArrayPropFoundInDefaultConfiguration() {
        // given
        String propertyKey = "Encryptor.ChooseIVMethod";    // property from ESAPI.properties in test res dir

        // when
        testPropertyManager = new EsapiPropertyManager();
        byte[] propertyValue = testPropertyManager.getByteArrayProp("Encryptor.ChooseIVMethod");

        // then
        assertNotNull(propertyValue);
    }

    @Test(expected = ConfigurationException.class)
    public void testByteArrayPropertyNotFoundByLoaderAndThrowException() {
        // given
        String propertyKey = "non.existing.property";

        // when
        testPropertyManager = new EsapiPropertyManager();
        testPropertyManager.loaders.clear();
        testPropertyManager.loaders.add(new StandardEsapiPropertyLoader(propFilename1, 1));
        testPropertyManager.getByteArrayProp(propertyKey);

        // then expect exception
    }

}
