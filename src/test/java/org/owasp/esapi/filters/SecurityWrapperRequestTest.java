/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2008-2018 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 */

package org.owasp.esapi.filters;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.SecurityConfiguration;
import org.owasp.esapi.Validator;
import org.owasp.esapi.errors.ValidationException;
// A hack for now; eventually, I plan to move this into a new org.owasp.esapi.PropNames class. -kww
import static org.owasp.esapi.reference.DefaultSecurityConfiguration.DISABLE_INTRUSION_DETECTION;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import javax.servlet.http.HttpServletRequest;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestName;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

/**
 * Unit tests for {@link SecurityWrapperRequest}.
 * <br/>
 * This test uses static context mocking! This can affect certain behaviors if it is executed in a JVM container with
 * other tests depending on the same static reference - Which is going to be everything.
 * <br/>
 * This may affect some test environments, mostly IDE's. It is not expected that this impacts the Maven build, as
 * surefire plugin isolates JVM's for tests during that phase.
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest(ESAPI.class)
public class SecurityWrapperRequestTest {
    private static final String ESAPI_VALIDATOR_GETTER_METHOD_NAME = "validator";
    private static final String ESAPY_SECURITY_CONFIGURATION_GETTER_METHOD_NAME = "securityConfiguration";
    private static final String SECURITY_CONFIGURATION_QUERY_STRING_LENGTH_KEY_NAME = "HttpUtilities.URILENGTH";
    private static final String SECURITY_CONFIGURATION_PARAMETER_STRING_LENGTH_KEY_NAME = "HttpUtilities.httpQueryParamValueLength";
    
    private static final int SECURITY_CONFIGURATION_TEST_LENGTH = 255;

    private static final String QUERY_STRING_CANONCALIZE_TYPE_KEY = "HTTPQueryString";
    private static final String PARAMETER_STRING_CANONCALIZE_TYPE_KEY = "HTTPParameterValue";
  
    @Rule
    public TestName testName = new TestName();

    @Mock
    private HttpServletRequest mockRequest;
    @Mock
    private Validator mockValidator;
    @Mock
    private SecurityConfiguration mockSecConfig;
    
    private String testQueryValue;
    private String testParameterName;
    private String testParameterValue;
    private String testValueCanonical;
    private String testValidatorType;
    private int testMaximumLength;

    @Before
    public void setup() throws Exception {
        PowerMockito.mockStatic(ESAPI.class);
        PowerMockito.when(ESAPI.class, ESAPI_VALIDATOR_GETTER_METHOD_NAME).thenReturn(mockValidator);
        PowerMockito.when(ESAPI.class, ESAPY_SECURITY_CONFIGURATION_GETTER_METHOD_NAME).thenReturn(mockSecConfig);
        //Is intrusion detection disabled?  A:  Yes, it is off.  
        //This logic is confusing:  True, the value is False...
        Mockito.when( mockSecConfig.getBooleanProp( DISABLE_INTRUSION_DETECTION ) ).thenReturn(true);
        
        testQueryValue = testName.getMethodName() + "_query_value";
        
        testParameterName = testName.getMethodName() + "_parameter_name";
        testParameterValue = testName.getMethodName() + "_parameter_value";  
        testValueCanonical = testName.getMethodName() + "_value_canonical";
        testValidatorType = testName.getMethodName() + "_validator_type";
        testMaximumLength = testName.getMethodName().length();
    }
    
    /**
     * Workflow test for happy-path getQueryString. Asserts delegation calls and parameters to delegate
     * behaviors.
     */
    @Test
    public void testGetQueryString() throws Exception {
        ValidatorTestContainer validatorTester = new ValidatorTestContainer(mockValidator);
        validatorTester.getValidInputReturns(testValueCanonical);

        PowerMockito.when(mockSecConfig.getIntProp(SECURITY_CONFIGURATION_QUERY_STRING_LENGTH_KEY_NAME)).thenReturn(
            SECURITY_CONFIGURATION_TEST_LENGTH);

        PowerMockito.when(mockRequest.getQueryString()).thenReturn(testQueryValue);

        SecurityWrapperRequest request = new SecurityWrapperRequest(mockRequest);
        String rval = request.getQueryString();
        assertEquals(testValueCanonical, rval);

        validatorTester.verify(testQueryValue, QUERY_STRING_CANONCALIZE_TYPE_KEY, SECURITY_CONFIGURATION_TEST_LENGTH, true);

        verify(mockSecConfig, times(1)).getIntProp(SECURITY_CONFIGURATION_QUERY_STRING_LENGTH_KEY_NAME);
        verify(mockRequest, times(1)).getQueryString();
    }

    /**
     * Test for getQueryString when validation throws an Exception. 
     * <br/>
     * Asserts delegation calls and parameters to delegate behaviors.
     */
    @Test
    public void testGetQueryStringCanonicalizeException() throws Exception {
        ValidatorTestContainer validatorTester = new ValidatorTestContainer(mockValidator);
        validatorTester.getValidInputThrows();

        PowerMockito.when(mockSecConfig.getIntProp(SECURITY_CONFIGURATION_QUERY_STRING_LENGTH_KEY_NAME)).thenReturn(
            SECURITY_CONFIGURATION_TEST_LENGTH);

        PowerMockito.when(mockRequest.getQueryString()).thenReturn(testQueryValue);

        SecurityWrapperRequest request = new SecurityWrapperRequest(mockRequest);
        String rval = request.getQueryString();

        assertTrue("SecurityWrapperRequest should return an empty String when an exception occurs in validation", rval
            .isEmpty());

        validatorTester.verify(testQueryValue, QUERY_STRING_CANONCALIZE_TYPE_KEY, SECURITY_CONFIGURATION_TEST_LENGTH, true);
        
        verify(mockSecConfig, times(1)).getIntProp(SECURITY_CONFIGURATION_QUERY_STRING_LENGTH_KEY_NAME);
        verify(mockRequest, times(1)).getQueryString();
    }
    @Test
    public void testGetParameterString() throws Exception{
        ValidatorTestContainer validatorTester = new ValidatorTestContainer(mockValidator);
        validatorTester.getValidInputReturns(testValueCanonical);
        
        PowerMockito.when(mockSecConfig.getIntProp(SECURITY_CONFIGURATION_PARAMETER_STRING_LENGTH_KEY_NAME)).thenReturn(
                SECURITY_CONFIGURATION_TEST_LENGTH);

        PowerMockito.when(mockRequest.getParameter(testParameterName)).thenReturn(testParameterValue);

        SecurityWrapperRequest request = new SecurityWrapperRequest(mockRequest);
        String rval = request.getParameter(testParameterName);
        assertEquals(testValueCanonical, rval);
        
        validatorTester.verify(testParameterValue, PARAMETER_STRING_CANONCALIZE_TYPE_KEY, SECURITY_CONFIGURATION_TEST_LENGTH, true);
        
        verify(mockSecConfig, times(1)).getIntProp(SECURITY_CONFIGURATION_PARAMETER_STRING_LENGTH_KEY_NAME);
        verify(mockRequest, times(1)).getParameter(testParameterName);
    }

    @Test
    public void testGetParameterStringBoolean() throws Exception{
        ValidatorTestContainer validatorTester = new ValidatorTestContainer(mockValidator);
        validatorTester.getValidInputReturns(testValueCanonical);
        PowerMockito.when(mockSecConfig.getIntProp(SECURITY_CONFIGURATION_PARAMETER_STRING_LENGTH_KEY_NAME)).thenReturn(
                SECURITY_CONFIGURATION_TEST_LENGTH);

        PowerMockito.when(mockRequest.getParameter(testParameterName)).thenReturn(testParameterValue);

        SecurityWrapperRequest request = new SecurityWrapperRequest(mockRequest);
        String rval = request.getParameter(testParameterName, false);
        assertEquals(testValueCanonical, rval);
        
        validatorTester.verify(testParameterValue, PARAMETER_STRING_CANONCALIZE_TYPE_KEY, SECURITY_CONFIGURATION_TEST_LENGTH, false);
        
        verify(mockSecConfig, times(1)).getIntProp(SECURITY_CONFIGURATION_PARAMETER_STRING_LENGTH_KEY_NAME);
        verify(mockRequest, times(1)).getParameter(testParameterName);
    }
    
    @Test
    public void testGetParameterStringBooleanInt() throws Exception{
        ValidatorTestContainer validatorTester = new ValidatorTestContainer(mockValidator);
        validatorTester.getValidInputReturns(testValueCanonical);
        
        PowerMockito.when(mockRequest.getParameter(testParameterName)).thenReturn(testParameterValue);

        SecurityWrapperRequest request = new SecurityWrapperRequest(mockRequest);
        String rval = request.getParameter(testParameterName, false, testMaximumLength);
        assertEquals(testValueCanonical, rval);

        validatorTester.verify(testParameterValue, PARAMETER_STRING_CANONCALIZE_TYPE_KEY, testMaximumLength, false);

        verify(mockRequest, times(1)).getParameter(testParameterName);
    }
    
    @Test
    public void testGetParameterStringBooleanIntString() throws Exception{
        ValidatorTestContainer validatorTester = new ValidatorTestContainer(mockValidator);
        validatorTester.getValidInputReturns(testValueCanonical);
      
        
        PowerMockito.when(mockRequest.getParameter(testParameterName)).thenReturn(testParameterValue);

        SecurityWrapperRequest request = new SecurityWrapperRequest(mockRequest);
        String rval = request.getParameter(testParameterName, false, testMaximumLength, testValidatorType);
        assertEquals(testValueCanonical, rval);

        validatorTester.verify(testParameterValue, testValidatorType, testMaximumLength, false);
     
        verify(mockRequest, times(1)).getParameter(testParameterName);
    }

    
    @Test
    public void testGetParameterStringNullEvalPassthrough() throws Exception{
        ValidatorTestContainer validatorTester = new ValidatorTestContainer(mockValidator);
        validatorTester.getValidInputReturns(null);
        
        PowerMockito.when(mockSecConfig.getIntProp(SECURITY_CONFIGURATION_PARAMETER_STRING_LENGTH_KEY_NAME)).thenReturn(
                SECURITY_CONFIGURATION_TEST_LENGTH);

        PowerMockito.when(mockRequest.getParameter(testParameterName)).thenReturn(testParameterValue);

        SecurityWrapperRequest request = new SecurityWrapperRequest(mockRequest);
        String rval = request.getParameter(testParameterName);
        assertNull(rval);
        
        validatorTester.verify(testParameterValue, PARAMETER_STRING_CANONCALIZE_TYPE_KEY, SECURITY_CONFIGURATION_TEST_LENGTH, true);

        verify(mockSecConfig, times(1)).getIntProp(SECURITY_CONFIGURATION_PARAMETER_STRING_LENGTH_KEY_NAME);
        verify(mockRequest, times(1)).getParameter(testParameterName);
    }

    @Test
    public void testGetParameterStringBooleanNullEvalPassthrough() throws Exception{
        ValidatorTestContainer validatorTester = new ValidatorTestContainer(mockValidator);
        validatorTester.getValidInputReturns(null);
        
        PowerMockito.when(mockSecConfig.getIntProp(SECURITY_CONFIGURATION_PARAMETER_STRING_LENGTH_KEY_NAME)).thenReturn(
                SECURITY_CONFIGURATION_TEST_LENGTH);

        PowerMockito.when(mockRequest.getParameter(testParameterName)).thenReturn(testParameterValue);

        SecurityWrapperRequest request = new SecurityWrapperRequest(mockRequest);
        String rval = request.getParameter(testParameterName, false);
        assertNull(rval);
        
        validatorTester.verify(testParameterValue, PARAMETER_STRING_CANONCALIZE_TYPE_KEY, SECURITY_CONFIGURATION_TEST_LENGTH, false);

        verify(mockSecConfig, times(1)).getIntProp(SECURITY_CONFIGURATION_PARAMETER_STRING_LENGTH_KEY_NAME);
        verify(mockRequest, times(1)).getParameter(testParameterName);
    }
    
    @Test
    public void testGetParameterStringBooleanIntNullEvalPassthrough() throws Exception{
        ValidatorTestContainer validatorTester = new ValidatorTestContainer(mockValidator);
        validatorTester.getValidInputReturns(null);
        
        PowerMockito.when(mockRequest.getParameter(testParameterName)).thenReturn(testParameterValue);

        SecurityWrapperRequest request = new SecurityWrapperRequest(mockRequest);
        String rval = request.getParameter(testParameterName, false, testMaximumLength);
        assertNull(rval);
        
        validatorTester.verify(testParameterValue, PARAMETER_STRING_CANONCALIZE_TYPE_KEY, testMaximumLength, false);

        verify(mockRequest, times(1)).getParameter(testParameterName);
    }
    
    @Test
    public void testGetParameterStringBooleanIntStringNullEvalPassthrough() throws Exception{
        ValidatorTestContainer validatorTester = new ValidatorTestContainer(mockValidator);
        validatorTester.getValidInputReturns(null);
        
        PowerMockito.when(mockRequest.getParameter(testParameterName)).thenReturn(testParameterValue);

        SecurityWrapperRequest request = new SecurityWrapperRequest(mockRequest);
        String rval = request.getParameter(testParameterName, false, testMaximumLength, testValidatorType);
        assertNull(rval);
        validatorTester.verify(testParameterValue, testValidatorType, testMaximumLength, false);

        verify(mockRequest, times(1)).getParameter(testParameterName);
    }
    
    @Test
    public void testGetParameterStringNullOnException() throws Exception{
        ValidatorTestContainer validatorTester = new ValidatorTestContainer(mockValidator);
        validatorTester.getValidInputThrows();
        
        PowerMockito.when(mockSecConfig.getIntProp(SECURITY_CONFIGURATION_PARAMETER_STRING_LENGTH_KEY_NAME)).thenReturn(
                SECURITY_CONFIGURATION_TEST_LENGTH);

        PowerMockito.when(mockRequest.getParameter(testParameterName)).thenReturn(testParameterValue);

        SecurityWrapperRequest request = new SecurityWrapperRequest(mockRequest);
        String rval = request.getParameter(testParameterName);
        assertNull(rval);

        validatorTester.verify(testParameterValue, PARAMETER_STRING_CANONCALIZE_TYPE_KEY, SECURITY_CONFIGURATION_TEST_LENGTH, true);
        
        verify(mockSecConfig, times(1)).getIntProp(SECURITY_CONFIGURATION_PARAMETER_STRING_LENGTH_KEY_NAME);
        verify(mockRequest, times(1)).getParameter(testParameterName);
    }
    
    

    @Test
    public void testGetParameterStringBooleanNullOnException() throws Exception{
        ValidatorTestContainer validatorTester = new ValidatorTestContainer(mockValidator);
        validatorTester.getValidInputThrows();
        
        PowerMockito.when(mockSecConfig.getIntProp(SECURITY_CONFIGURATION_PARAMETER_STRING_LENGTH_KEY_NAME)).thenReturn(
                SECURITY_CONFIGURATION_TEST_LENGTH);

        PowerMockito.when(mockRequest.getParameter(testParameterName)).thenReturn(testParameterValue);

        SecurityWrapperRequest request = new SecurityWrapperRequest(mockRequest);
        String rval = request.getParameter(testParameterName, false);
        assertNull(rval);
        
        validatorTester.verify(testParameterValue, PARAMETER_STRING_CANONCALIZE_TYPE_KEY, SECURITY_CONFIGURATION_TEST_LENGTH, false);
    
        verify(mockSecConfig, times(1)).getIntProp(SECURITY_CONFIGURATION_PARAMETER_STRING_LENGTH_KEY_NAME);
        verify(mockRequest, times(1)).getParameter(testParameterName);
    }
    
    @Test
    public void testGetParameterStringBooleanIntNullOnException() throws Exception{
        ValidatorTestContainer validatorTester = new ValidatorTestContainer(mockValidator);
        validatorTester.getValidInputThrows();
        
        PowerMockito.when(mockRequest.getParameter(testParameterName)).thenReturn(testParameterValue);

        SecurityWrapperRequest request = new SecurityWrapperRequest(mockRequest);
        String rval = request.getParameter(testParameterName, false, testMaximumLength);
        assertNull(rval);
        
        validatorTester.verify(testParameterValue, PARAMETER_STRING_CANONCALIZE_TYPE_KEY, testMaximumLength, false);
        verify(mockRequest, times(1)).getParameter(testParameterName);
    }
    
    @Test
    public void testGetParameterStringBooleanIntStringNullOnException() throws Exception{
        ValidatorTestContainer validatorTester = new ValidatorTestContainer(mockValidator);
        validatorTester.getValidInputThrows();

        PowerMockito.when(mockRequest.getParameter(testParameterName)).thenReturn(testParameterValue);

        SecurityWrapperRequest request = new SecurityWrapperRequest(mockRequest);
        String rval = request.getParameter(testParameterName, false, testMaximumLength, testValidatorType);
        assertNull(rval);
        
        validatorTester.verify(testParameterValue, testValidatorType, testMaximumLength, false);
       
        verify(mockRequest, times(1)).getParameter(testParameterName);
    }

    /**
     * Utility test class meant to encapsulate common interactions for preparing and
     * verifying the Validator interactions common to multiple tests.
     *
     */
    private class ValidatorTestContainer {
        private ArgumentCaptor<String> inputCapture = ArgumentCaptor.forClass(String.class);
        private ArgumentCaptor<String> typeCapture = ArgumentCaptor.forClass(String.class);
        private ArgumentCaptor<Integer> lengthCapture = ArgumentCaptor.forClass(Integer.class);
        private ArgumentCaptor<Boolean> allowNullCapture = ArgumentCaptor.forClass(Boolean.class);
        private Validator validator;
        
        
        public ValidatorTestContainer(Validator validatorRef) {
            this.validator = validatorRef;
        }
        public Answer<String> throwException() {
            return new Answer<String>() {
                @Override
                public String answer(InvocationOnMock invocation) throws Throwable {
                    throw new ValidationException("Thrown from test Scope", "Test Exception is intentional.");
                }
            };
        }
        
        public Answer<String> returnResult(final String result) {
            return new Answer<String>() {
                @Override
                public String answer(InvocationOnMock invocation) throws Throwable {
                    return result;
                }
            };
        }
        public void getValidInputReturns(String response) throws Exception {
            setupFor(returnResult(response));
        }
        
        public void getValidInputThrows() throws Exception {
            setupFor(throwException());
        }
        
        public void setupFor(Answer<String> answer) throws Exception {
            String context = anyString();
            String input = inputCapture.capture();
            String type = typeCapture.capture();
            Integer length = lengthCapture.capture();
            Boolean allowNull = allowNullCapture.capture();

            PowerMockito.when(validator.getValidInput(context, input, type, length, allowNull)).thenAnswer(answer);
        }
        
        public void verify(String input, String type, int maxLen, boolean allowNull) throws Exception {
            String actualInput = inputCapture.getValue();
            String actualType = typeCapture.getValue();
            int actualLength = lengthCapture.getValue().intValue();
            boolean actualAllowNull = allowNullCapture.getValue().booleanValue();

            assertEquals(input, actualInput);
            assertEquals(type, actualType);
            assertTrue(maxLen == actualLength);
            assertEquals(allowNull, actualAllowNull);
            
            Mockito.verify(validator, times(1)).getValidInput(anyString(), ArgumentMatchers.eq(input), ArgumentMatchers.eq(type), ArgumentMatchers.eq(maxLen), ArgumentMatchers.eq(allowNull));
        }
    }
}
