package org.owasp.esapi.filters;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.owasp.esapi.PropNames.DISABLE_INTRUSION_DETECTION;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestName;
import org.junit.runner.RunWith;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Logger;
import org.owasp.esapi.SecurityConfiguration;
import org.owasp.esapi.Validator;
import org.owasp.esapi.errors.ValidationException;
import org.owasp.esapi.http.MockHttpServletResponse;
import org.owasp.esapi.util.TestUtils;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

//@PrepareForTest({SecurityWrapperResponse.class})
@RunWith(PowerMockRunner.class)
@PrepareForTest(ESAPI.class)
@PowerMockIgnore({"com.sun.org.apache.xerces.*", "javax.xml.*", "org.xml.*", "org.w3c.dom.*"})
public class SecurityWrapperResponseTest {
    private static final String HEADER_NAME_CONTEXT = "HTTPHeaderName";
    private static final String HEADER_VALUE_CONTEXT = "HTTPHeaderValue";
    private static final String SEC_CTX_MAX_HEADER_NAME_SIZE_ATTR = "HttpUtilities.MaxHeaderNameSize";
    private static final String SEC_CTX_MAX_HEADER_VALUE_SIZE_ATTR = "HttpUtilities.MaxHeaderValueSize";


    @Rule
    public TestName testName = new TestName();

    @Mock
    private HttpServletResponse mockResponse;
    @Mock
    private Validator mockValidator;
    @Mock
    private SecurityConfiguration mockSecConfig;
    @Mock
    private Logger mockLogger;

    private String goodHeaderName;
    private String goodHeaderValue;

    @Before
    public void setup() throws Exception {
        //preconfig will impact other tests unless isolated.  Still don't want to duplicate it though.
        if (testName.getMethodName().startsWith("testSetHeader") ||
                testName.getMethodName().startsWith("testAddHeader")) {
            PowerMockito.mockStatic(ESAPI.class);
            PowerMockito.when(ESAPI.class, SecurityWrapperRequestTest.ESAPI_VALIDATOR_GETTER_METHOD_NAME).thenReturn(mockValidator);
            PowerMockito.when(ESAPI.class, SecurityWrapperRequestTest.ESAPI_GET_LOGGER_METHOD_NAME, "SecurityWrapperResponse").thenReturn(mockLogger);
            PowerMockito.when(ESAPI.class, SecurityWrapperRequestTest.ESAPY_SECURITY_CONFIGURATION_GETTER_METHOD_NAME).thenReturn(mockSecConfig);
            //Is intrusion detection disabled?  A:  Yes, it is off.
            //This logic is confusing:  True, the value is False...
            Mockito.when( mockSecConfig.getBooleanProp( DISABLE_INTRUSION_DETECTION ) ).thenReturn(true);

            goodHeaderName = testName.getMethodName() + "_goodHeaderName";
            goodHeaderValue = testName.getMethodName() + "_goodHeaderValue";
        }
    }

    @Test
    public void testSetHeaderHappyPath() throws Exception {
        String validateNameResponse = goodHeaderName;
        String validateValueResponse = goodHeaderValue;
        PowerMockito.when(mockValidator.getValidInput(anyString(), ArgumentMatchers.eq(goodHeaderName),
                ArgumentMatchers.eq(HEADER_NAME_CONTEXT),
                ArgumentMatchers.eq(SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH),
                ArgumentMatchers.eq(false))).thenReturn(validateNameResponse);

        PowerMockito.when(mockValidator.getValidInput(anyString(), ArgumentMatchers.eq(goodHeaderValue),
                ArgumentMatchers.eq(HEADER_VALUE_CONTEXT),
                ArgumentMatchers.eq(SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH),
                ArgumentMatchers.eq(false))).thenReturn(validateValueResponse);

        PowerMockito.when(mockSecConfig.getIntProp(SEC_CTX_MAX_HEADER_NAME_SIZE_ATTR)).thenReturn(
                SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH);

        PowerMockito.when(mockSecConfig.getIntProp(SEC_CTX_MAX_HEADER_VALUE_SIZE_ATTR)).thenReturn(
                SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH);

        SecurityWrapperResponse response = new SecurityWrapperResponse(mockResponse);

        response.setHeader(goodHeaderName, goodHeaderValue);

        verify(mockValidator, times(1)).getValidInput(anyString(), ArgumentMatchers.eq(goodHeaderName), ArgumentMatchers.eq(HEADER_NAME_CONTEXT), ArgumentMatchers.eq(SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH), ArgumentMatchers.eq(false));
        verify(mockValidator, times(1)).getValidInput(anyString(), ArgumentMatchers.eq(goodHeaderValue), ArgumentMatchers.eq(HEADER_VALUE_CONTEXT), ArgumentMatchers.eq(SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH), ArgumentMatchers.eq(false));
        verify(mockSecConfig, times(1)).getIntProp(SEC_CTX_MAX_HEADER_NAME_SIZE_ATTR);
        verify(mockSecConfig, times(1)).getIntProp(SEC_CTX_MAX_HEADER_VALUE_SIZE_ATTR);
        verify(mockResponse, times(1)).setHeader(validateNameResponse, validateValueResponse);
        verify(mockLogger,times(0)).warning(ArgumentMatchers.any(org.owasp.esapi.Logger.EventType.class), anyString(), ArgumentMatchers.any(Exception.class));
    }

    @Test
    public void testSetHeaderNameNull() throws Exception {
        String validateNameResponse = null;
        String validateValueResponse = goodHeaderValue;
        PowerMockito.when(mockValidator.getValidInput(anyString(), ArgumentMatchers.eq(goodHeaderName),
                ArgumentMatchers.eq(HEADER_NAME_CONTEXT),
                ArgumentMatchers.eq(SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH),
                ArgumentMatchers.eq(false))).thenReturn(validateNameResponse);

        PowerMockito.when(mockValidator.getValidInput(anyString(), ArgumentMatchers.eq(goodHeaderValue),
                ArgumentMatchers.eq(HEADER_VALUE_CONTEXT),
                ArgumentMatchers.eq(SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH),
                ArgumentMatchers.eq(false))).thenReturn(validateValueResponse);

        PowerMockito.when(mockSecConfig.getIntProp(SEC_CTX_MAX_HEADER_NAME_SIZE_ATTR)).thenReturn(
                SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH);

        PowerMockito.when(mockSecConfig.getIntProp(SEC_CTX_MAX_HEADER_VALUE_SIZE_ATTR)).thenReturn(
                SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH);

        SecurityWrapperResponse response = new SecurityWrapperResponse(mockResponse);

        response.setHeader(goodHeaderName, goodHeaderValue);

        verify(mockValidator, times(1)).getValidInput(anyString(), ArgumentMatchers.eq(goodHeaderName),
                ArgumentMatchers.eq(HEADER_NAME_CONTEXT),
                ArgumentMatchers.eq(SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH),
                ArgumentMatchers.eq(false));
        verify(mockValidator, times(1)).getValidInput(anyString(), ArgumentMatchers.eq(goodHeaderValue),
                ArgumentMatchers.eq(HEADER_VALUE_CONTEXT),
                ArgumentMatchers.eq(SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH),
                ArgumentMatchers.eq(false));
        verify(mockSecConfig, times(1)).getIntProp(SEC_CTX_MAX_HEADER_NAME_SIZE_ATTR);
        verify(mockSecConfig, times(1)).getIntProp(SEC_CTX_MAX_HEADER_VALUE_SIZE_ATTR);
        verify(mockResponse, times(0)).setHeader(anyString(), anyString());
        verify(mockLogger, times(0)).warning(ArgumentMatchers.any(org.owasp.esapi.Logger.EventType.class),anyString(),
                ArgumentMatchers.any(Exception.class));
    }

    @Test
    public void testSetHeaderNameEmpty() throws Exception {
        String validateNameResponse = "     ";
        String validateValueResponse = goodHeaderValue;
        PowerMockito.when(mockValidator.getValidInput(anyString(), ArgumentMatchers.eq(goodHeaderName),
                ArgumentMatchers.eq(HEADER_NAME_CONTEXT),
                ArgumentMatchers.eq(SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH),
                ArgumentMatchers.eq(false))).thenReturn(validateNameResponse);

        PowerMockito.when(mockValidator.getValidInput(anyString(), ArgumentMatchers.eq(goodHeaderValue),
                ArgumentMatchers.eq(HEADER_VALUE_CONTEXT),
                ArgumentMatchers.eq(SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH),
                ArgumentMatchers.eq(false))).thenReturn(validateValueResponse);

        PowerMockito.when(mockSecConfig.getIntProp(SEC_CTX_MAX_HEADER_NAME_SIZE_ATTR)).thenReturn(
                SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH);

        PowerMockito.when(mockSecConfig.getIntProp(SEC_CTX_MAX_HEADER_VALUE_SIZE_ATTR)).thenReturn(
                SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH);

        SecurityWrapperResponse response = new SecurityWrapperResponse(mockResponse);

        response.setHeader(goodHeaderName, goodHeaderValue);

        verify(mockValidator, times(1)).getValidInput(anyString(), ArgumentMatchers.eq(goodHeaderName),
                ArgumentMatchers.eq(HEADER_NAME_CONTEXT),
                ArgumentMatchers.eq(SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH),
                ArgumentMatchers.eq(false));
        verify(mockValidator, times(1)).getValidInput(anyString(), ArgumentMatchers.eq(goodHeaderValue),
                ArgumentMatchers.eq(HEADER_VALUE_CONTEXT),
                ArgumentMatchers.eq(SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH),
                ArgumentMatchers.eq(false));
        verify(mockSecConfig, times(1)).getIntProp(SEC_CTX_MAX_HEADER_NAME_SIZE_ATTR);
        verify(mockSecConfig, times(1)).getIntProp(SEC_CTX_MAX_HEADER_VALUE_SIZE_ATTR);
        verify(mockResponse, times(0)).setHeader(anyString(), anyString());
        verify(mockLogger, times(0)).warning(ArgumentMatchers.any(org.owasp.esapi.Logger.EventType.class),anyString(),
                ArgumentMatchers.any(Exception.class));
    }

    @Test
    public void testSetHeaderNameThrowsValidationException() throws Exception {
        String validateValueResponse = goodHeaderValue;
        PowerMockito.when(mockValidator.getValidInput(anyString(), ArgumentMatchers.eq(goodHeaderName),
                ArgumentMatchers.eq(HEADER_NAME_CONTEXT),
                ArgumentMatchers.eq(SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH),
                ArgumentMatchers.eq(false))).thenThrow(ValidationException.class);

        PowerMockito.when(mockValidator.getValidInput(anyString(), ArgumentMatchers.eq(goodHeaderValue),
                ArgumentMatchers.eq(HEADER_VALUE_CONTEXT),
                ArgumentMatchers.eq(SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH),
                ArgumentMatchers.eq(false))).thenReturn(validateValueResponse);

        PowerMockito.when(mockSecConfig.getIntProp(SEC_CTX_MAX_HEADER_NAME_SIZE_ATTR)).thenReturn(
                SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH);

        PowerMockito.when(mockSecConfig.getIntProp(SEC_CTX_MAX_HEADER_VALUE_SIZE_ATTR)).thenReturn(
                SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH);

        SecurityWrapperResponse response = new SecurityWrapperResponse(mockResponse);

        response.setHeader(goodHeaderName, goodHeaderValue);

        verify(mockValidator, times(1)).getValidInput(anyString(), ArgumentMatchers.eq(goodHeaderName),
                ArgumentMatchers.eq(HEADER_NAME_CONTEXT),
                ArgumentMatchers.eq(SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH),
                ArgumentMatchers.eq(false));
        verify(mockValidator, times(1)).getValidInput(anyString(), ArgumentMatchers.eq(goodHeaderValue),
                ArgumentMatchers.eq(HEADER_VALUE_CONTEXT),
                ArgumentMatchers.eq(SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH),
                ArgumentMatchers.eq(false));
        verify(mockSecConfig, times(1)).getIntProp(SEC_CTX_MAX_HEADER_NAME_SIZE_ATTR);
        verify(mockSecConfig, times(1)).getIntProp(SEC_CTX_MAX_HEADER_VALUE_SIZE_ATTR);
        verify(mockResponse, times(0)).setHeader(anyString(), anyString());

        verify(mockLogger, times(1)).warning(ArgumentMatchers.any(org.owasp.esapi.Logger.EventType.class),
                ArgumentMatchers.contains("Attempt to set invalid header NAME denied: HTTPHeaderName:"+ goodHeaderName),
                ArgumentMatchers.any(Exception.class));
    }

    @Test
    public void testSetHeaderValueNull() throws Exception {
        String validateNameResponse = goodHeaderName;
        String validateValueResponse = null;
        PowerMockito.when(mockValidator.getValidInput(anyString(), ArgumentMatchers.eq(goodHeaderName),
                ArgumentMatchers.eq(HEADER_NAME_CONTEXT),
                ArgumentMatchers.eq(SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH),
                ArgumentMatchers.eq(false))).thenReturn(validateNameResponse);

        PowerMockito.when(mockValidator.getValidInput(anyString(), ArgumentMatchers.eq(goodHeaderValue),
                ArgumentMatchers.eq(HEADER_VALUE_CONTEXT),
                ArgumentMatchers.eq(SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH),
                ArgumentMatchers.eq(false))).thenReturn(validateValueResponse);

        PowerMockito.when(mockSecConfig.getIntProp(SEC_CTX_MAX_HEADER_NAME_SIZE_ATTR)).thenReturn(
                SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH);

        PowerMockito.when(mockSecConfig.getIntProp(SEC_CTX_MAX_HEADER_VALUE_SIZE_ATTR)).thenReturn(
                SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH);

        SecurityWrapperResponse response = new SecurityWrapperResponse(mockResponse);

        response.setHeader(goodHeaderName, goodHeaderValue);

        verify(mockValidator, times(1)).getValidInput(anyString(), ArgumentMatchers.eq(goodHeaderName),
                ArgumentMatchers.eq(HEADER_NAME_CONTEXT),
                ArgumentMatchers.eq(SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH),
                ArgumentMatchers.eq(false));
        verify(mockValidator, times(1)).getValidInput(anyString(), ArgumentMatchers.eq(goodHeaderValue),
                ArgumentMatchers.eq(HEADER_VALUE_CONTEXT),
                ArgumentMatchers.eq(SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH),
                ArgumentMatchers.eq(false));
        verify(mockSecConfig, times(1)).getIntProp(SEC_CTX_MAX_HEADER_NAME_SIZE_ATTR);
        verify(mockSecConfig, times(1)).getIntProp(SEC_CTX_MAX_HEADER_VALUE_SIZE_ATTR);
        verify(mockResponse, times(0)).setHeader(anyString(), anyString());
        verify(mockLogger, times(0)).warning(ArgumentMatchers.any(org.owasp.esapi.Logger.EventType.class),anyString(),
                ArgumentMatchers.any(Exception.class));
    }

    @Test
    public void testSetHeaderValueEmpty() throws Exception {
        String validateNameResponse = goodHeaderName;
        String validateValueResponse = "     ";
        PowerMockito.when(mockValidator.getValidInput(anyString(), ArgumentMatchers.eq(goodHeaderName),
                ArgumentMatchers.eq(HEADER_NAME_CONTEXT),
                ArgumentMatchers.eq(SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH),
                ArgumentMatchers.eq(false))).thenReturn(validateNameResponse);

        PowerMockito.when(mockValidator.getValidInput(anyString(), ArgumentMatchers.eq(goodHeaderValue),
                ArgumentMatchers.eq(HEADER_VALUE_CONTEXT),
                ArgumentMatchers.eq(SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH),
                ArgumentMatchers.eq(false))).thenReturn(validateValueResponse);

        PowerMockito.when(mockSecConfig.getIntProp(SEC_CTX_MAX_HEADER_NAME_SIZE_ATTR)).thenReturn(
                SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH);

        PowerMockito.when(mockSecConfig.getIntProp(SEC_CTX_MAX_HEADER_VALUE_SIZE_ATTR)).thenReturn(
                SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH);

        SecurityWrapperResponse response = new SecurityWrapperResponse(mockResponse);

        response.setHeader(goodHeaderName, goodHeaderValue);

        verify(mockValidator, times(1)).getValidInput(anyString(), ArgumentMatchers.eq(goodHeaderName),
                ArgumentMatchers.eq(HEADER_NAME_CONTEXT),
                ArgumentMatchers.eq(SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH),
                ArgumentMatchers.eq(false));
        verify(mockValidator, times(1)).getValidInput(anyString(), ArgumentMatchers.eq(goodHeaderValue),
                ArgumentMatchers.eq(HEADER_VALUE_CONTEXT),
                ArgumentMatchers.eq(SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH),
                ArgumentMatchers.eq(false));
        verify(mockSecConfig, times(1)).getIntProp(SEC_CTX_MAX_HEADER_NAME_SIZE_ATTR);
        verify(mockSecConfig, times(1)).getIntProp(SEC_CTX_MAX_HEADER_VALUE_SIZE_ATTR);
        verify(mockResponse, times(0)).setHeader(anyString(), anyString());
        verify(mockLogger, times(0)).warning(ArgumentMatchers.any(org.owasp.esapi.Logger.EventType.class),anyString(),
                ArgumentMatchers.any(Exception.class));
    }

    @Test
    public void testSetHeaderValueThrowsValidationException() throws Exception {
        String validateNameResponse = goodHeaderName;
        PowerMockito.when(mockValidator.getValidInput(anyString(), ArgumentMatchers.eq(goodHeaderName),
                ArgumentMatchers.eq(HEADER_NAME_CONTEXT),
                ArgumentMatchers.eq(SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH),
                ArgumentMatchers.eq(false))).thenReturn(validateNameResponse);

        PowerMockito.when(mockValidator.getValidInput(anyString(), ArgumentMatchers.eq(goodHeaderValue),
                ArgumentMatchers.eq(HEADER_VALUE_CONTEXT),
                ArgumentMatchers.eq(SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH),
                ArgumentMatchers.eq(false))).thenThrow(ValidationException.class);

        PowerMockito.when(mockSecConfig.getIntProp(SEC_CTX_MAX_HEADER_NAME_SIZE_ATTR)).thenReturn(
                SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH);

        PowerMockito.when(mockSecConfig.getIntProp(SEC_CTX_MAX_HEADER_VALUE_SIZE_ATTR)).thenReturn(
                SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH);

        SecurityWrapperResponse response = new SecurityWrapperResponse(mockResponse);

        response.setHeader(goodHeaderName, goodHeaderValue);

        verify(mockValidator, times(1)).getValidInput(anyString(), ArgumentMatchers.eq(goodHeaderName),
                ArgumentMatchers.eq(HEADER_NAME_CONTEXT),
                ArgumentMatchers.eq(SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH),
                ArgumentMatchers.eq(false));
        verify(mockValidator, times(1)).getValidInput(anyString(), ArgumentMatchers.eq(goodHeaderValue),
                ArgumentMatchers.eq(HEADER_VALUE_CONTEXT),
                ArgumentMatchers.eq(SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH),
                ArgumentMatchers.eq(false));
        verify(mockSecConfig, times(1)).getIntProp(SEC_CTX_MAX_HEADER_NAME_SIZE_ATTR);
        verify(mockSecConfig, times(1)).getIntProp(SEC_CTX_MAX_HEADER_VALUE_SIZE_ATTR);
        verify(mockResponse, times(0)).setHeader(anyString(), anyString());

        verify(mockLogger, times(1)).warning(ArgumentMatchers.any(org.owasp.esapi.Logger.EventType.class),
                ArgumentMatchers.contains("Attempt to set invalid header VALUE denied: HTTPHeaderName:"+ goodHeaderName),
                ArgumentMatchers.any(Exception.class));
    }

    @Test
    public void testAddHeaderHappyPath() throws Exception {
        String validateNameResponse = goodHeaderName;
        String validateValueResponse = goodHeaderValue;
        PowerMockito.when(mockValidator.getValidInput(anyString(), ArgumentMatchers.eq(goodHeaderName),
                ArgumentMatchers.eq(HEADER_NAME_CONTEXT),
                ArgumentMatchers.eq(SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH),
                ArgumentMatchers.eq(false))).thenReturn(validateNameResponse);

        PowerMockito.when(mockValidator.getValidInput(anyString(), ArgumentMatchers.eq(goodHeaderValue),
                ArgumentMatchers.eq(HEADER_VALUE_CONTEXT),
                ArgumentMatchers.eq(SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH),
                ArgumentMatchers.eq(false))).thenReturn(validateValueResponse);

        PowerMockito.when(mockSecConfig.getIntProp(SEC_CTX_MAX_HEADER_NAME_SIZE_ATTR)).thenReturn(
                SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH);

        PowerMockito.when(mockSecConfig.getIntProp(SEC_CTX_MAX_HEADER_VALUE_SIZE_ATTR)).thenReturn(
                SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH);

        SecurityWrapperResponse response = new SecurityWrapperResponse(mockResponse);

        response.addHeader(goodHeaderName, goodHeaderValue);

        verify(mockValidator, times(1)).getValidInput(anyString(), ArgumentMatchers.eq(goodHeaderName), ArgumentMatchers.eq(HEADER_NAME_CONTEXT), ArgumentMatchers.eq(SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH), ArgumentMatchers.eq(false));
        verify(mockValidator, times(1)).getValidInput(anyString(), ArgumentMatchers.eq(goodHeaderValue), ArgumentMatchers.eq(HEADER_VALUE_CONTEXT), ArgumentMatchers.eq(SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH), ArgumentMatchers.eq(false));
        verify(mockSecConfig, times(1)).getIntProp(SEC_CTX_MAX_HEADER_NAME_SIZE_ATTR);
        verify(mockSecConfig, times(1)).getIntProp(SEC_CTX_MAX_HEADER_VALUE_SIZE_ATTR);
        verify(mockResponse, times(1)).addHeader(validateNameResponse, validateValueResponse);
        verify(mockLogger,times(0)).warning(ArgumentMatchers.any(org.owasp.esapi.Logger.EventType.class), anyString(), ArgumentMatchers.any(Exception.class));
    }

    @Test
    public void testAddHeaderNameNull() throws Exception {
        String validateNameResponse = null;
        String validateValueResponse = goodHeaderValue;
        PowerMockito.when(mockValidator.getValidInput(anyString(), ArgumentMatchers.eq(goodHeaderName),
                ArgumentMatchers.eq(HEADER_NAME_CONTEXT),
                ArgumentMatchers.eq(SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH),
                ArgumentMatchers.eq(false))).thenReturn(validateNameResponse);

        PowerMockito.when(mockValidator.getValidInput(anyString(), ArgumentMatchers.eq(goodHeaderValue),
                ArgumentMatchers.eq(HEADER_VALUE_CONTEXT),
                ArgumentMatchers.eq(SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH),
                ArgumentMatchers.eq(false))).thenReturn(validateValueResponse);

        PowerMockito.when(mockSecConfig.getIntProp(SEC_CTX_MAX_HEADER_NAME_SIZE_ATTR)).thenReturn(
                SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH);

        PowerMockito.when(mockSecConfig.getIntProp(SEC_CTX_MAX_HEADER_VALUE_SIZE_ATTR)).thenReturn(
                SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH);

        SecurityWrapperResponse response = new SecurityWrapperResponse(mockResponse);

        response.addHeader(goodHeaderName, goodHeaderValue);

        verify(mockValidator, times(1)).getValidInput(anyString(), ArgumentMatchers.eq(goodHeaderName),
                ArgumentMatchers.eq(HEADER_NAME_CONTEXT),
                ArgumentMatchers.eq(SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH),
                ArgumentMatchers.eq(false));
        verify(mockValidator, times(1)).getValidInput(anyString(), ArgumentMatchers.eq(goodHeaderValue),
                ArgumentMatchers.eq(HEADER_VALUE_CONTEXT),
                ArgumentMatchers.eq(SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH),
                ArgumentMatchers.eq(false));
        verify(mockSecConfig, times(1)).getIntProp(SEC_CTX_MAX_HEADER_NAME_SIZE_ATTR);
        verify(mockSecConfig, times(1)).getIntProp(SEC_CTX_MAX_HEADER_VALUE_SIZE_ATTR);
        verify(mockResponse, times(0)).addHeader(anyString(), anyString());
        verify(mockLogger, times(0)).warning(ArgumentMatchers.any(org.owasp.esapi.Logger.EventType.class),anyString(),
                ArgumentMatchers.any(Exception.class));
    }

    @Test
    public void testAddHeaderNameEmpty() throws Exception {
        String validateNameResponse = "     ";
        String validateValueResponse = goodHeaderValue;
        PowerMockito.when(mockValidator.getValidInput(anyString(), ArgumentMatchers.eq(goodHeaderName),
                ArgumentMatchers.eq(HEADER_NAME_CONTEXT),
                ArgumentMatchers.eq(SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH),
                ArgumentMatchers.eq(false))).thenReturn(validateNameResponse);

        PowerMockito.when(mockValidator.getValidInput(anyString(), ArgumentMatchers.eq(goodHeaderValue),
                ArgumentMatchers.eq(HEADER_VALUE_CONTEXT),
                ArgumentMatchers.eq(SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH),
                ArgumentMatchers.eq(false))).thenReturn(validateValueResponse);

        PowerMockito.when(mockSecConfig.getIntProp(SEC_CTX_MAX_HEADER_NAME_SIZE_ATTR)).thenReturn(
                SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH);

        PowerMockito.when(mockSecConfig.getIntProp(SEC_CTX_MAX_HEADER_VALUE_SIZE_ATTR)).thenReturn(
                SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH);

        SecurityWrapperResponse response = new SecurityWrapperResponse(mockResponse);

        response.addHeader(goodHeaderName, goodHeaderValue);

        verify(mockValidator, times(1)).getValidInput(anyString(), ArgumentMatchers.eq(goodHeaderName),
                ArgumentMatchers.eq(HEADER_NAME_CONTEXT),
                ArgumentMatchers.eq(SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH),
                ArgumentMatchers.eq(false));
        verify(mockValidator, times(1)).getValidInput(anyString(), ArgumentMatchers.eq(goodHeaderValue),
                ArgumentMatchers.eq(HEADER_VALUE_CONTEXT),
                ArgumentMatchers.eq(SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH),
                ArgumentMatchers.eq(false));
        verify(mockSecConfig, times(1)).getIntProp(SEC_CTX_MAX_HEADER_NAME_SIZE_ATTR);
        verify(mockSecConfig, times(1)).getIntProp(SEC_CTX_MAX_HEADER_VALUE_SIZE_ATTR);
        verify(mockResponse, times(0)).addHeader(anyString(), anyString());
        verify(mockLogger, times(0)).warning(ArgumentMatchers.any(org.owasp.esapi.Logger.EventType.class),anyString(),
                ArgumentMatchers.any(Exception.class));
    }

    @Test
    public void testAddHeaderNameThrowsValidationException() throws Exception {
        String validateValueResponse = goodHeaderValue;
        PowerMockito.when(mockValidator.getValidInput(anyString(), ArgumentMatchers.eq(goodHeaderName),
                ArgumentMatchers.eq(HEADER_NAME_CONTEXT),
                ArgumentMatchers.eq(SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH),
                ArgumentMatchers.eq(false))).thenThrow(ValidationException.class);

        PowerMockito.when(mockValidator.getValidInput(anyString(), ArgumentMatchers.eq(goodHeaderValue),
                ArgumentMatchers.eq(HEADER_VALUE_CONTEXT),
                ArgumentMatchers.eq(SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH),
                ArgumentMatchers.eq(false))).thenReturn(validateValueResponse);

        PowerMockito.when(mockSecConfig.getIntProp(SEC_CTX_MAX_HEADER_NAME_SIZE_ATTR)).thenReturn(
                SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH);

        PowerMockito.when(mockSecConfig.getIntProp(SEC_CTX_MAX_HEADER_VALUE_SIZE_ATTR)).thenReturn(
                SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH);

        SecurityWrapperResponse response = new SecurityWrapperResponse(mockResponse);

        response.addHeader(goodHeaderName, goodHeaderValue);

        verify(mockValidator, times(1)).getValidInput(anyString(), ArgumentMatchers.eq(goodHeaderName),
                ArgumentMatchers.eq(HEADER_NAME_CONTEXT),
                ArgumentMatchers.eq(SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH),
                ArgumentMatchers.eq(false));
        verify(mockValidator, times(1)).getValidInput(anyString(), ArgumentMatchers.eq(goodHeaderValue),
                ArgumentMatchers.eq(HEADER_VALUE_CONTEXT),
                ArgumentMatchers.eq(SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH),
                ArgumentMatchers.eq(false));
        verify(mockSecConfig, times(1)).getIntProp(SEC_CTX_MAX_HEADER_NAME_SIZE_ATTR);
        verify(mockSecConfig, times(1)).getIntProp(SEC_CTX_MAX_HEADER_VALUE_SIZE_ATTR);
        verify(mockResponse, times(0)).addHeader(anyString(), anyString());

        verify(mockLogger, times(1)).warning(ArgumentMatchers.any(org.owasp.esapi.Logger.EventType.class),
                ArgumentMatchers.contains("Attempt to add invalid header NAME denied: HTTPHeaderName:"+ goodHeaderName ),
                ArgumentMatchers.any(Exception.class));
    }

    @Test
    public void testAddHeaderValueNull() throws Exception {
        String validateNameResponse = goodHeaderName;
        String validateValueResponse = null;
        PowerMockito.when(mockValidator.getValidInput(anyString(), ArgumentMatchers.eq(goodHeaderName),
                ArgumentMatchers.eq(HEADER_NAME_CONTEXT),
                ArgumentMatchers.eq(SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH),
                ArgumentMatchers.eq(false))).thenReturn(validateNameResponse);

        PowerMockito.when(mockValidator.getValidInput(anyString(), ArgumentMatchers.eq(goodHeaderValue),
                ArgumentMatchers.eq(HEADER_VALUE_CONTEXT),
                ArgumentMatchers.eq(SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH),
                ArgumentMatchers.eq(false))).thenReturn(validateValueResponse);

        PowerMockito.when(mockSecConfig.getIntProp(SEC_CTX_MAX_HEADER_NAME_SIZE_ATTR)).thenReturn(
                SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH);

        PowerMockito.when(mockSecConfig.getIntProp(SEC_CTX_MAX_HEADER_VALUE_SIZE_ATTR)).thenReturn(
                SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH);

        SecurityWrapperResponse response = new SecurityWrapperResponse(mockResponse);

        response.addHeader(goodHeaderName, goodHeaderValue);

        verify(mockValidator, times(1)).getValidInput(anyString(), ArgumentMatchers.eq(goodHeaderName),
                ArgumentMatchers.eq(HEADER_NAME_CONTEXT),
                ArgumentMatchers.eq(SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH),
                ArgumentMatchers.eq(false));
        verify(mockValidator, times(1)).getValidInput(anyString(), ArgumentMatchers.eq(goodHeaderValue),
                ArgumentMatchers.eq(HEADER_VALUE_CONTEXT),
                ArgumentMatchers.eq(SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH),
                ArgumentMatchers.eq(false));
        verify(mockSecConfig, times(1)).getIntProp(SEC_CTX_MAX_HEADER_NAME_SIZE_ATTR);
        verify(mockSecConfig, times(1)).getIntProp(SEC_CTX_MAX_HEADER_VALUE_SIZE_ATTR);
        verify(mockResponse, times(0)).addHeader(anyString(), anyString());
        verify(mockLogger, times(0)).warning(ArgumentMatchers.any(org.owasp.esapi.Logger.EventType.class),anyString(),
                ArgumentMatchers.any(Exception.class));
    }

    @Test
    public void testAddHeaderValueEmpty() throws Exception {
        String validateNameResponse = goodHeaderName;
        String validateValueResponse = "     ";
        PowerMockito.when(mockValidator.getValidInput(anyString(), ArgumentMatchers.eq(goodHeaderName),
                ArgumentMatchers.eq(HEADER_NAME_CONTEXT),
                ArgumentMatchers.eq(SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH),
                ArgumentMatchers.eq(false))).thenReturn(validateNameResponse);

        PowerMockito.when(mockValidator.getValidInput(anyString(), ArgumentMatchers.eq(goodHeaderValue),
                ArgumentMatchers.eq(HEADER_VALUE_CONTEXT),
                ArgumentMatchers.eq(SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH),
                ArgumentMatchers.eq(false))).thenReturn(validateValueResponse);

        PowerMockito.when(mockSecConfig.getIntProp(SEC_CTX_MAX_HEADER_NAME_SIZE_ATTR)).thenReturn(
                SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH);

        PowerMockito.when(mockSecConfig.getIntProp(SEC_CTX_MAX_HEADER_VALUE_SIZE_ATTR)).thenReturn(
                SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH);

        SecurityWrapperResponse response = new SecurityWrapperResponse(mockResponse);

        response.addHeader(goodHeaderName, goodHeaderValue);

        verify(mockValidator, times(1)).getValidInput(anyString(), ArgumentMatchers.eq(goodHeaderName),
                ArgumentMatchers.eq(HEADER_NAME_CONTEXT),
                ArgumentMatchers.eq(SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH),
                ArgumentMatchers.eq(false));
        verify(mockValidator, times(1)).getValidInput(anyString(), ArgumentMatchers.eq(goodHeaderValue),
                ArgumentMatchers.eq(HEADER_VALUE_CONTEXT),
                ArgumentMatchers.eq(SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH),
                ArgumentMatchers.eq(false));
        verify(mockSecConfig, times(1)).getIntProp(SEC_CTX_MAX_HEADER_NAME_SIZE_ATTR);
        verify(mockSecConfig, times(1)).getIntProp(SEC_CTX_MAX_HEADER_VALUE_SIZE_ATTR);
        verify(mockResponse, times(0)).addHeader(anyString(), anyString());
        verify(mockLogger, times(0)).warning(ArgumentMatchers.any(org.owasp.esapi.Logger.EventType.class),anyString(),
                ArgumentMatchers.any(Exception.class));
    }

    @Test
    public void testAddHeaderValueThrowsValidationException() throws Exception {
        String validateNameResponse = goodHeaderName;
        PowerMockito.when(mockValidator.getValidInput(anyString(), ArgumentMatchers.eq(goodHeaderName),
                ArgumentMatchers.eq(HEADER_NAME_CONTEXT),
                ArgumentMatchers.eq(SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH),
                ArgumentMatchers.eq(false))).thenReturn(validateNameResponse);

        PowerMockito.when(mockValidator.getValidInput(anyString(), ArgumentMatchers.eq(goodHeaderValue),
                ArgumentMatchers.eq(HEADER_VALUE_CONTEXT),
                ArgumentMatchers.eq(SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH),
                ArgumentMatchers.eq(false))).thenThrow(ValidationException.class);

        PowerMockito.when(mockSecConfig.getIntProp(SEC_CTX_MAX_HEADER_NAME_SIZE_ATTR)).thenReturn(
                SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH);

        PowerMockito.when(mockSecConfig.getIntProp(SEC_CTX_MAX_HEADER_VALUE_SIZE_ATTR)).thenReturn(
                SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH);

        SecurityWrapperResponse response = new SecurityWrapperResponse(mockResponse);

        response.addHeader(goodHeaderName, goodHeaderValue);

        verify(mockValidator, times(1)).getValidInput(anyString(), ArgumentMatchers.eq(goodHeaderName),
                ArgumentMatchers.eq(HEADER_NAME_CONTEXT),
                ArgumentMatchers.eq(SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH),
                ArgumentMatchers.eq(false));
        verify(mockValidator, times(1)).getValidInput(anyString(), ArgumentMatchers.eq(goodHeaderValue),
                ArgumentMatchers.eq(HEADER_VALUE_CONTEXT),
                ArgumentMatchers.eq(SecurityWrapperRequestTest.SECURITY_CONFIGURATION_TEST_LENGTH),
                ArgumentMatchers.eq(false));
        verify(mockSecConfig, times(1)).getIntProp(SEC_CTX_MAX_HEADER_NAME_SIZE_ATTR);
        verify(mockSecConfig, times(1)).getIntProp(SEC_CTX_MAX_HEADER_VALUE_SIZE_ATTR);
        verify(mockResponse, times(0)).addHeader(anyString(), anyString());

        verify(mockLogger, times(1)).warning(ArgumentMatchers.any(org.owasp.esapi.Logger.EventType.class),
                ArgumentMatchers.contains("Attempt to add invalid header VALUE denied: HTTPHeaderName:"+ goodHeaderName),
                ArgumentMatchers.any(Exception.class));
    }

    @Test
    public void testAddRefererHeader(){
        HttpServletResponse servResp = mock(HttpServletResponse.class);
        SecurityWrapperResponse resp = new SecurityWrapperResponse(servResp);
        resp.addReferer("http://127.0.0.1:3000/campaigns?goal=all&section=active&sort-by=-id&status=Draft%2CLaunched");
        verify(servResp, times(1)).addHeader("referer", "");
    }

    @Test
    public void testAddDateHeader(){
        HttpServletResponse servResp = mock(HttpServletResponse.class);
        SecurityWrapperResponse resp = new SecurityWrapperResponse(servResp);
        long currentTime = System.currentTimeMillis();
        resp.addDateHeader("Foo", currentTime);
        verify(servResp, times(1)).addDateHeader("Foo", currentTime);
    }

    @Test
    public void testSetDateHeader(){
        HttpServletResponse servResp = mock(HttpServletResponse.class);
        SecurityWrapperResponse resp = new SecurityWrapperResponse(servResp);
        long currentTime = System.currentTimeMillis();
        resp.setDateHeader("Foo", currentTime);
        verify(servResp, times(1)).setDateHeader("Foo", currentTime);
    }

    @Test
    public void testSetInvalidDateHeader(){
        HttpServletResponse servResp = mock(HttpServletResponse.class);
        SecurityWrapperResponse resp = new SecurityWrapperResponse(servResp);
        long currentTime = System.currentTimeMillis();
        resp.setDateHeader("<scr", currentTime);
        verify(servResp, times(0)).setDateHeader("<scr", currentTime);
    }

    @Test
    public void testSetInvalidHeader(){
        HttpServletResponse servResp = mock(HttpServletResponse.class);
        SecurityWrapperResponse resp = new SecurityWrapperResponse(servResp);
        resp.setHeader("foo", "<script>alert</script>");
        verify(servResp, times(0)).setHeader("foo", "<script>alert</script>");
    }

    @Test
    public void testInvalidDateHeader(){
        HttpServletResponse servResp = mock(HttpServletResponse.class);
        SecurityWrapperResponse resp = new SecurityWrapperResponse(servResp);
        long currentTime = System.currentTimeMillis();
        resp.addDateHeader("Foo\\r\\n", currentTime);
        verify(servResp, times(0)).addDateHeader("Foo", currentTime);
    }

    @Test
    public void testAddHeaderInvalidValueLength(){
        //refactor this to use a spy.
        HttpServletResponse servResp = mock(HttpServletResponse.class);
        SecurityWrapperResponse resp = new SecurityWrapperResponse(servResp);
        SecurityWrapperResponse spyResp = spy(resp);
        Mockito.doCallRealMethod().when(spyResp).addHeader("Foo", TestUtils.generateStringOfLength(4097));
        resp.addHeader("Foo", TestUtils.generateStringOfLength(4097));
        verify(servResp, times(0)).addHeader("Foo", "bar");
    }

    @Test
    public void testAddHeaderInvalidKeyLength(){
        HttpServletResponse servResp = mock(HttpServletResponse.class);
        SecurityWrapperResponse resp = new SecurityWrapperResponse(servResp);
        resp.addHeader(TestUtils.generateStringOfLength(257), "bar");
        verify(servResp, times(0)).addHeader("Foo", "bar");
    }

    @Test
    public void testAddIntHeader(){
        HttpServletResponse servResp = mock(HttpServletResponse.class);
        SecurityWrapperResponse resp = new SecurityWrapperResponse(servResp);
        resp.addIntHeader("aaaa", 4);
        verify(servResp, times(1)).addIntHeader("aaaa", 4);
    }

    @Test
    public void testAddInvalidIntHeader(){
        HttpServletResponse servResp = mock(HttpServletResponse.class);
        SecurityWrapperResponse resp = new SecurityWrapperResponse(servResp);
        resp.addIntHeader(TestUtils.generateStringOfLength(257), Integer.MIN_VALUE);
        verify(servResp, times(0)).addIntHeader(TestUtils.generateStringOfLength(257), Integer.MIN_VALUE);
    }

    @Test
    public void testContainsHeader(){
        HttpServletResponse servResp = new MockHttpServletResponse();
        servResp = spy(servResp);
        SecurityWrapperResponse resp = new SecurityWrapperResponse(servResp);
        resp = spy(resp);
        resp.addIntHeader("aaaa", Integer.MIN_VALUE);
        verify(servResp, times(1)).addIntHeader("aaaa", Integer.MIN_VALUE);
        assertEquals(true, servResp.containsHeader("aaaa"));
    }

    @Test
    public void testAddValidCookie(){
        HttpServletResponse servResp = new MockHttpServletResponse();
        servResp = spy(servResp);
        SecurityWrapperResponse resp = new SecurityWrapperResponse(servResp);
        SecurityWrapperResponse spyResp = spy(resp);
        Cookie cookie = new Cookie("Foo", TestUtils.generateStringOfLength(10));
        cookie.setMaxAge(5000);
        Mockito.doCallRealMethod().when(spyResp).addCookie(cookie);
        spyResp.addCookie(cookie);

        /*
         * We're indirectly testing our class.  Since it ultimately
         * delegates to HttpServletResponse.addHeader, we're actually
         * validating that our test method constructs a header with the
         * expected properties.  This implicitly tests the
         * createCookieHeader method as well.
         */
        verify(servResp, times(1)).addHeader("Set-Cookie", "Foo=aaaaaaaaaa; Max-Age=5000; Secure; HttpOnly");
    }

    @Test
    public void testAddValidCookieWithDomain(){
        HttpServletResponse servResp = new MockHttpServletResponse();
        servResp = spy(servResp);
        SecurityWrapperResponse resp = new SecurityWrapperResponse(servResp);
        SecurityWrapperResponse spyResp = spy(resp);
        Cookie cookie = new Cookie("Foo", TestUtils.generateStringOfLength(10));
        cookie.setDomain("evil.com");
        cookie.setMaxAge(-1);
        Mockito.doCallRealMethod().when(spyResp).addCookie(cookie);
        spyResp.addCookie(cookie);
        verify(servResp, times(1)).addHeader("Set-Cookie", "Foo=aaaaaaaaaa; Domain=evil.com; Secure; HttpOnly");
    }

    @Test
    public void testAddValidCookieWithPath(){
        HttpServletResponse servResp = new MockHttpServletResponse();
        servResp = spy(servResp);
        SecurityWrapperResponse resp = new SecurityWrapperResponse(servResp);
        SecurityWrapperResponse spyResp = spy(resp);
        Cookie cookie = new Cookie("Foo", TestUtils.generateStringOfLength(10));
        cookie.setDomain("evil.com");
        cookie.setPath("/foo/bar");
        Mockito.doCallRealMethod().when(spyResp).addCookie(cookie);
        spyResp.addCookie(cookie);
        verify(servResp, times(1)).addHeader("Set-Cookie", "Foo=aaaaaaaaaa; Domain=evil.com; Path=/foo/bar; Secure; HttpOnly");
    }

    @Test
    public void testAddInValidCookie(){
        HttpServletResponse servResp = new MockHttpServletResponse();
        servResp = spy(servResp);
        SecurityWrapperResponse resp = new SecurityWrapperResponse(servResp);
        SecurityWrapperResponse spyResp = spy(resp);
        Cookie cookie = new Cookie("Foo", TestUtils.generateStringOfLength(5000));
        Mockito.doCallRealMethod().when(spyResp).addCookie(cookie);

        spyResp.addCookie(cookie);
        verify(servResp, times(0)).addHeader("Set-Cookie", "Foo=" + TestUtils.generateStringOfLength(5000) + "; Secure; HttpOnly");
    }

    @Test
    public void testSendError() throws Exception{
        HttpServletResponse servResp = new MockHttpServletResponse();
        servResp = spy(servResp);
        SecurityWrapperResponse resp = new SecurityWrapperResponse(servResp);
        SecurityWrapperResponse spyResp = spy(resp);
        Mockito.doCallRealMethod().when(spyResp).sendError(200);
        spyResp.sendError(200);

        verify(servResp, times(1)).sendError(200, "HTTP error code: 200");;
    }

    @Test
    public void testSendStatus() throws Exception{
        HttpServletResponse servResp = new MockHttpServletResponse();
        servResp = spy(servResp);
        SecurityWrapperResponse resp = new SecurityWrapperResponse(servResp);
        SecurityWrapperResponse spyResp = spy(resp);
        Mockito.doCallRealMethod().when(spyResp).setStatus(200);;
        spyResp.setStatus(200);

        verify(servResp, times(1)).setStatus(200);;
    }

    @Test
    public void testSendStatusWithString() throws Exception{
        HttpServletResponse servResp = new MockHttpServletResponse();
        servResp = spy(servResp);
        SecurityWrapperResponse resp = new SecurityWrapperResponse(servResp);
        SecurityWrapperResponse spyResp = spy(resp);
        Mockito.doCallRealMethod().when(spyResp).setStatus(200, "foo");;
        spyResp.setStatus(200, "foo");

        verify(servResp, times(1)).sendError(200, "foo");;
    }
}
