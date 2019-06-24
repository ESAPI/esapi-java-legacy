package org.owasp.esapi.configuration;

import org.junit.Before;
import org.junit.Test;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.configuration.consts.EsapiConfiguration;
import org.owasp.esapi.errors.ConfigurationException;

import java.io.File;
import java.io.IOException;
import java.io.FileNotFoundException;

import static junit.framework.Assert.*;

public class EsapiPropertyManagerTest {

    private static String propFilename1;
    private static String propFilename2;
    private static String xmlFilename1;
    private static String xmlFilename2;
    private static final String noSuchFile = "/invalidDir/noSubDir/nosuchFile.xml";

    private EsapiPropertyManager testPropertyManager;

    @Before
    public void init() {
        System.setProperty(EsapiConfiguration.DEVTEAM_ESAPI_CFG.getConfigName(), "");
        System.setProperty(EsapiConfiguration.OPSTEAM_ESAPI_CFG.getConfigName(), "");
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
        // given
        System.setProperty(EsapiConfiguration.DEVTEAM_ESAPI_CFG.getConfigName(), propFilename1);
        System.setProperty(EsapiConfiguration.OPSTEAM_ESAPI_CFG.getConfigName(), propFilename2);

        // when
        try {
            testPropertyManager = new EsapiPropertyManager();
        } catch (IOException e) {
            fail(e.getMessage());
        }

        // then
        assertNotNull(testPropertyManager.loaders);
        assertNotSame(0, testPropertyManager.loaders.size());
    }

    @Test
    public void testStringPropFoundInLoader() {
        // given
        System.setProperty(EsapiConfiguration.DEVTEAM_ESAPI_CFG.getConfigName(), xmlFilename1);
        String propertyKey = "string_property";
        String expectedPropertyValue = "test_string_property";

        // when
        try {
            testPropertyManager = new EsapiPropertyManager();
        } catch (IOException e) {
            fail(e.getMessage());
        }
        String propertyValue = testPropertyManager.getStringProp(propertyKey);

        // then
        assertEquals(expectedPropertyValue, propertyValue);
    }

    @Test
    public void testStringPropertyLoadedFromFileWithHigherPriority() {
        // given
        System.setProperty(EsapiConfiguration.DEVTEAM_ESAPI_CFG.getConfigName(), propFilename1);
        System.setProperty(EsapiConfiguration.OPSTEAM_ESAPI_CFG.getConfigName(), xmlFilename2);

        String propertyKey = "string_property";
        String expectedValue = "test_string_property_2";

        // when
        try {
            testPropertyManager = new EsapiPropertyManager();
        } catch (IOException e) {
            fail(e.getMessage());
        }
        String propertyValue = testPropertyManager.getStringProp(propertyKey);

        // then
        assertEquals(expectedValue, propertyValue);
    }

    @Test
    public void testStringPropertyLoadedFromPropFileWithHigherPriority() {
        // given
        System.setProperty(EsapiConfiguration.DEVTEAM_ESAPI_CFG.getConfigName(), propFilename1);
        System.setProperty(EsapiConfiguration.OPSTEAM_ESAPI_CFG.getConfigName(), propFilename2);
        String propertyKey = "string_property";
        String expectedValue = "test_string_property_2";

        // when
        try {
            testPropertyManager = new EsapiPropertyManager();
        } catch (IOException e) {
            fail(e.getMessage());
        }
        String propertyValue = testPropertyManager.getStringProp(propertyKey);

        // then
        assertEquals(expectedValue, propertyValue);
    }

    @Test
    public void testStringPropertyLoadedFromXmlFileWithHigherPriority() {
        // given
        System.setProperty(EsapiConfiguration.DEVTEAM_ESAPI_CFG.getConfigName(), xmlFilename1);
        System.setProperty(EsapiConfiguration.OPSTEAM_ESAPI_CFG.getConfigName(), xmlFilename2);
        String propertyKey = "string_property";
        String expectedValue = "test_string_property_2";

        // when
        try {
            testPropertyManager = new EsapiPropertyManager();
        } catch (IOException e) {
            fail(e.getMessage());
        }
        String propertyValue = testPropertyManager.getStringProp(propertyKey);

        // then
        assertEquals(expectedValue, propertyValue);
    }


    @Test(expected = ConfigurationException.class)
    public void testStringPropertyNotFoundByLoaderAndThrowException() {
        // given
        System.setProperty(EsapiConfiguration.DEVTEAM_ESAPI_CFG.getConfigName(), propFilename1);
        String propertyKey = "non.existing.property";

        // when
        try {
            testPropertyManager = new EsapiPropertyManager();
        } catch (IOException e) {
            fail(e.getMessage());
        }
        testPropertyManager.getStringProp(propertyKey);

        // then expect exception
    }

    @Test
    public void testIntPropFoundInLoader() {
        // given
        System.setProperty(EsapiConfiguration.DEVTEAM_ESAPI_CFG.getConfigName(), xmlFilename1);
        String propertyKey = "int_property";
        int expectedPropertyValue = 5;

        // when
        try {
            testPropertyManager = new EsapiPropertyManager();
        } catch (IOException e) {
            fail(e.getMessage());
        }
        int propertyValue = testPropertyManager.getIntProp(propertyKey);

        // then
        assertEquals(expectedPropertyValue, propertyValue);
    }

    @Test
    public void testIntPropertyLoadedFromFileWithHigherPriority() {
        // given
        System.setProperty(EsapiConfiguration.DEVTEAM_ESAPI_CFG.getConfigName(), propFilename1);
        System.setProperty(EsapiConfiguration.OPSTEAM_ESAPI_CFG.getConfigName(), xmlFilename2);
        String propertyKey = "int_property";
        int expectedValue = 52;

        // when
        try {
            testPropertyManager = new EsapiPropertyManager();
        } catch (IOException e) {
            fail(e.getMessage());
        }
        int propertyValue = testPropertyManager.getIntProp(propertyKey);

        // then
        assertEquals(expectedValue, propertyValue);
    }

    @Test
    public void testIntPropertyLoadedFromPropFileWithHigherPriority() {
        // given
        System.setProperty(EsapiConfiguration.DEVTEAM_ESAPI_CFG.getConfigName(), propFilename1);
        System.setProperty(EsapiConfiguration.OPSTEAM_ESAPI_CFG.getConfigName(), propFilename2);
        String propertyKey = "int_property";
        int expectedValue = 52;    // value from ESAPI-test-2.properties file

        // when
        try {
            testPropertyManager = new EsapiPropertyManager();
        } catch (IOException e) {
            fail(e.getMessage());
        }
        int propertyValue = testPropertyManager.getIntProp(propertyKey);

        // then
        assertEquals(expectedValue, propertyValue);
    }

    @Test
    public void testIntPropertyLoadedFromXmlFileWithHigherPriority() {
        // given
        System.setProperty(EsapiConfiguration.DEVTEAM_ESAPI_CFG.getConfigName(), xmlFilename1);
        System.setProperty(EsapiConfiguration.OPSTEAM_ESAPI_CFG.getConfigName(), xmlFilename2);
        String propertyKey = "int_property";
        int expectedValue = 52;

        // when
        try {
            testPropertyManager = new EsapiPropertyManager();
        } catch (IOException e) {
            fail(e.getMessage());
        }
        int propertyValue = testPropertyManager.getIntProp(propertyKey);

        // then
        assertEquals(expectedValue, propertyValue);
    }


    @Test(expected = ConfigurationException.class)
    public void testIntPropertyNotFoundByLoaderAndThrowException() {
        // given
        String propertyKey = "non.existing.property";

        // when
        try {
            testPropertyManager = new EsapiPropertyManager();
        } catch (IOException e) {
            fail(e.getMessage());
        }
        testPropertyManager.getIntProp(propertyKey);

        // then expect exception
    }

    @Test
    public void testBooleanPropFoundInLoader() {
        // given
        System.setProperty(EsapiConfiguration.DEVTEAM_ESAPI_CFG.getConfigName(), xmlFilename1);
        String propertyKey = "boolean_property";
        boolean expectedPropertyValue = true;

        // when
        try {
            testPropertyManager = new EsapiPropertyManager();
        } catch (IOException e) {
            fail(e.getMessage());
        }
        boolean propertyValue = testPropertyManager.getBooleanProp(propertyKey);

        // then
        assertEquals(expectedPropertyValue, propertyValue);
    }

    @Test(expected = ConfigurationException.class)
    public void testBooleanPropertyNotFoundByLoaderAndThrowException() {
        // given
        String propertyKey = "non.existing.property";

        // when
        try {
            testPropertyManager = new EsapiPropertyManager();
        } catch (IOException e) {
            fail(e.getMessage());
        }
        testPropertyManager.getBooleanProp(propertyKey);

        // then expect exception
    }

    @Test
    public void testByteArrayPropFoundInLoader() {
        // given
        System.setProperty(EsapiConfiguration.DEVTEAM_ESAPI_CFG.getConfigName(), propFilename1);
        String propertyKey = "string_property";
        byte[] expectedValue = new byte[0];
        try {
            expectedValue = ESAPI.encoder().decodeFromBase64("test_string_property");
        } catch (IOException e) {
            fail(e.getMessage());
        }

        // when
        try {
            testPropertyManager = new EsapiPropertyManager();
        } catch (IOException e) {
            fail(e.getMessage());
        }
        byte[] propertyValue = testPropertyManager.getByteArrayProp(propertyKey);

        // then
        assertEquals(expectedValue, propertyValue);
    }

    @Test
    public void testByteArrayPropertyLoadedFromFileWithHigherPriority() {
        // given
        System.setProperty(EsapiConfiguration.DEVTEAM_ESAPI_CFG.getConfigName(), propFilename1);
        System.setProperty(EsapiConfiguration.OPSTEAM_ESAPI_CFG.getConfigName(), xmlFilename2);
        String propertyKey = "string_property";
        byte[] expectedValue = new byte[0];
        try {
            expectedValue = ESAPI.encoder().decodeFromBase64("test_string_property_2");
        } catch (IOException e) {
            fail(e.getMessage());
        }

        // when
        try {
            testPropertyManager = new EsapiPropertyManager();
        } catch (IOException e) {
            fail(e.getMessage());
        }
        byte[] propertyValue = testPropertyManager.getByteArrayProp(propertyKey);

        // then
        assertEquals(expectedValue, propertyValue);
    }

    @Test
    public void testByteArrayPropertyLoadedFromPropFileWithHigherPriority() {
        // given
        System.setProperty(EsapiConfiguration.DEVTEAM_ESAPI_CFG.getConfigName(), propFilename1);
        System.setProperty(EsapiConfiguration.OPSTEAM_ESAPI_CFG.getConfigName(), propFilename2);
        String propertyKey = "string_property";
        byte[] expectedValue = new byte[0];
        try {
            expectedValue = ESAPI.encoder().decodeFromBase64("test_string_property_2");
        } catch (IOException e) {
            fail(e.getMessage());
        }

        // when
        try {
            testPropertyManager = new EsapiPropertyManager();
        } catch (IOException e) {
            fail(e.getMessage());
        }
        byte[] propertyValue = testPropertyManager.getByteArrayProp(propertyKey);

        // then
        assertEquals(expectedValue, propertyValue);
    }

    @Test
    public void testByteArrayPropertyLoadedFromXmlFileWithHigherPriority() {
        // given
        System.setProperty(EsapiConfiguration.DEVTEAM_ESAPI_CFG.getConfigName(), xmlFilename1);
        System.setProperty(EsapiConfiguration.OPSTEAM_ESAPI_CFG.getConfigName(), xmlFilename2);
        String propertyKey = "string_property";
        byte[] expectedValue = new byte[0];
        try {
            expectedValue = ESAPI.encoder().decodeFromBase64("test_string_property_2");
        } catch (IOException e) {
            fail(e.getMessage());
        }

        // when
        try {
            testPropertyManager = new EsapiPropertyManager();
        } catch (IOException e) {
            fail(e.getMessage());
        }
        byte[] propertyValue = testPropertyManager.getByteArrayProp(propertyKey);

        // then
        assertEquals(expectedValue, propertyValue);
    }

    @Test(expected = ConfigurationException.class)
    public void testByteArrayPropertyNotFoundByLoaderAndThrowException() {
        // given
        String propertyKey = "non.existing.property";

        // when
        try {
            testPropertyManager = new EsapiPropertyManager();
        } catch (IOException e) {
            fail(e.getMessage());
        }
        testPropertyManager.getByteArrayProp(propertyKey);

        // then expect exception
    }


    @Test
    public void testExpectFileNotFoundException() {
        // given
        System.setProperty(EsapiConfiguration.DEVTEAM_ESAPI_CFG.getConfigName(), noSuchFile);

        // when
        try {
            testPropertyManager = new EsapiPropertyManager();
        } catch (IOException e) {
            if ( e instanceof FileNotFoundException ) {
                return;
            } else {
                fail("testExpectFileNotFoundException(): Was expecting FileNotFoundException for IOException. Exception:" + e);
            }
        }
        
        fail("Did not throw expected IOException for property file " + noSuchFile);
    }
}
