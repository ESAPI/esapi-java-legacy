package org.owasp.esapi.reference;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;

import java.util.regex.Pattern;

import org.hamcrest.core.Is;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.rules.TestName;
import org.junit.runner.RunWith;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Encoder;
import org.owasp.esapi.SecurityConfiguration;
import org.owasp.esapi.ValidationErrorList;
import org.owasp.esapi.errors.ValidationException;
import org.owasp.esapi.reference.validation.StringValidationRule;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

/**
 * This class contains a subsection of tests of the DefaultValidator class 
 * SPECIFIC TO THE INPUT 'STRING' VALIDATION API.
 * 
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest({DefaultValidator.class, ESAPI.class})
public class DefaultValidatorInputStringAPITest {
    private static final String ESAPY_SECURITY_CONFIGURATION_GETTER_METHOD_NAME = "securityConfiguration";
    private static final Pattern TEST_PATTERN = Pattern.compile("");
    @Rule
    public ExpectedException exEx = ExpectedException.none();
    @Rule
    public TestName testName = new TestName();
    @Mock
    private SecurityConfiguration mockSecConfig;
    @Mock
    private Encoder mockEncoder;

    private ValidationException validationEx;
    private String contextStr;
    private StringValidationRule spyStringRule;
    private ValidationErrorList errors = new ValidationErrorList();
    
    private DefaultValidator uit;
    private String testValidatorType;
    private String validatorResultString;
    private int testMaximumLength;
    
    @Before
    public void setup() throws Exception {
        contextStr = testName.getMethodName();
        testValidatorType = testName.getMethodName() + "_validator_type";
        validatorResultString = testName.getMethodName() + "_validator_result";
        testMaximumLength = testName.getMethodName().length();
        
        validationEx = new ValidationException(contextStr, contextStr);
        
        mockEncoder = mock(Encoder.class);
        uit = new DefaultValidator(mockEncoder);
        
        //Don't care how the StringValidationRule works, we just care that we forwarded the information as expected.
        spyStringRule = new StringValidationRule(testValidatorType, mockEncoder); 
        spyStringRule = spy(spyStringRule);
        doNothing().when(spyStringRule).addWhitelistPattern(ArgumentMatchers.<Pattern>any());
        doNothing().when(spyStringRule).setAllowNull(ArgumentMatchers.anyBoolean());
        doNothing().when(spyStringRule).setMaximumLength(ArgumentMatchers.anyInt());
        doReturn(validatorResultString).when(spyStringRule).getValid(ArgumentMatchers.anyString(), ArgumentMatchers.anyString());
        whenNew(StringValidationRule.class).withArguments(eq(testValidatorType), eq(mockEncoder)).thenReturn(spyStringRule);
        
        errors = spy(errors);
        whenNew(ValidationErrorList.class).withNoArguments().thenReturn(errors);
        
        
        PowerMockito.mockStatic(ESAPI.class);
        PowerMockito.when(ESAPI.class, ESAPY_SECURITY_CONFIGURATION_GETTER_METHOD_NAME).thenReturn(mockSecConfig);
        
        
        when(mockSecConfig.getValidationPattern(testValidatorType)).thenReturn(TEST_PATTERN);
        
    }
    
    @After
    public void verifyDelegateCalls() {
        verify(mockSecConfig, times(1)).getValidationPattern(testValidatorType);
        
        PowerMockito.verifyNoMoreInteractions(spyStringRule, mockSecConfig, mockEncoder);
    }
    
    @Test
    public void getValidInputNullAllowedPassthrough() throws Exception {
        String safeValue =  uit.getValidInput(contextStr, testName.getMethodName(), testValidatorType, testMaximumLength, true);
        assertEquals(validatorResultString, safeValue);
        verify(spyStringRule, times(1)).addWhitelistPattern(TEST_PATTERN);
        verify(spyStringRule, times(1)).setAllowNull(true);
        verify(spyStringRule, times(0)).setAllowNull(false);
        verify(spyStringRule, times(1)).setMaximumLength(testMaximumLength);
        verify(spyStringRule, times(1)).setCanonicalize(true);
        verify(spyStringRule, times(1)).getValid(contextStr, testName.getMethodName());
    }
    
    @Test
    public void getValidInputNullNotAllowedPassthrough() throws Exception {
        String safeValue =  uit.getValidInput(contextStr, testName.getMethodName(), testValidatorType, testMaximumLength, false);
        assertEquals(validatorResultString, safeValue);
        verify(spyStringRule, times(1)).addWhitelistPattern(TEST_PATTERN);
        verify(spyStringRule, times(0)).setAllowNull(true);
        verify(spyStringRule, times(1)).setAllowNull(false);
        verify(spyStringRule, times(1)).setMaximumLength(testMaximumLength);
        verify(spyStringRule, times(1)).setCanonicalize(true);
        verify(spyStringRule, times(1)).getValid(contextStr, testName.getMethodName());
    }
    
    @Test
    public void getValidInputNullPatternThrows() throws Exception {
        exEx.expect(IllegalArgumentException.class);
        exEx.expectMessage(testValidatorType + "] was not set via the ESAPI validation configuration");
        when(mockSecConfig.getValidationPattern(testValidatorType)).thenReturn(null);
    
        uit.getValidInput(contextStr, testName.getMethodName(), testValidatorType, testMaximumLength, true);
    }
    
    @Test
    public void getValidInputValidationExceptionPropagates() throws Exception {
        exEx.expect(Is.is(validationEx));

        doThrow(validationEx).when(spyStringRule).getValid(ArgumentMatchers.anyString(), ArgumentMatchers.anyString());
        try {
            uit.getValidInput(contextStr, testName.getMethodName(), testValidatorType, testMaximumLength, true);
        } finally {
            verify(spyStringRule, times(1)).addWhitelistPattern(TEST_PATTERN);
            verify(spyStringRule, times(1)).setAllowNull(true);
            verify(spyStringRule, times(0)).setAllowNull(false);
            verify(spyStringRule, times(1)).setMaximumLength(testMaximumLength);
            verify(spyStringRule, times(1)).setCanonicalize(true);
            verify(spyStringRule, times(1)).getValid(contextStr, testName.getMethodName());
        }
    }
    
    @Test
    public void getValidInputValidationExceptionErrorList() throws Exception {
        ValidationErrorList errorList = new ValidationErrorList();

        doThrow(validationEx).when(spyStringRule).getValid(ArgumentMatchers.anyString(), ArgumentMatchers.anyString());
       String result = uit.getValidInput(contextStr, testName.getMethodName(), testValidatorType, testMaximumLength, true,errorList);
        assertTrue(result.isEmpty());
        assertEquals(1, errorList.size());
        assertEquals(validationEx, errorList.getError(contextStr));
        verify(spyStringRule, times(1)).addWhitelistPattern(TEST_PATTERN);
        verify(spyStringRule, times(1)).setAllowNull(true);
        verify(spyStringRule, times(0)).setAllowNull(false);
        verify(spyStringRule, times(1)).setMaximumLength(testMaximumLength);
        verify(spyStringRule, times(1)).setCanonicalize(true);
        verify(spyStringRule, times(1)).getValid(contextStr, testName.getMethodName());
    }
    
    
    @Test
    public void isValidInputNullAllowedPassthrough() throws Exception {
        boolean isValid=  uit.isValidInput(contextStr, testName.getMethodName(), testValidatorType, testMaximumLength, true);
        assertTrue(isValid);
        
        verify(spyStringRule, times(1)).addWhitelistPattern(TEST_PATTERN);
        verify(spyStringRule, times(1)).setAllowNull(true);
        verify(spyStringRule, times(0)).setAllowNull(false);
        verify(spyStringRule, times(1)).setMaximumLength(testMaximumLength);
        verify(spyStringRule, times(1)).setCanonicalize(true);
        verify(spyStringRule, times(1)).getValid(contextStr, testName.getMethodName());
    }
    
    @Test
    public void isValidInputValidationExceptionReturnsFalse() throws Exception {
        doThrow(validationEx).when(spyStringRule).getValid(ArgumentMatchers.anyString(), ArgumentMatchers.anyString());
        boolean result = uit.isValidInput(contextStr, testName.getMethodName(), testValidatorType, testMaximumLength, true);
        assertFalse(result);
        verify(spyStringRule, times(1)).addWhitelistPattern(TEST_PATTERN);
        verify(spyStringRule, times(1)).setAllowNull(true);
        verify(spyStringRule, times(0)).setAllowNull(false);
        verify(spyStringRule, times(1)).setMaximumLength(testMaximumLength);
        verify(spyStringRule, times(1)).setCanonicalize(true);
        verify(spyStringRule, times(1)).getValid(contextStr, testName.getMethodName());
    }
    
    @Test
    public void isValidInputValidationExceptionErrorListReturnsFalse() throws Exception {
        ValidationErrorList errorList = new ValidationErrorList();

        doThrow(validationEx).when(spyStringRule).getValid(ArgumentMatchers.anyString(), ArgumentMatchers.anyString());
        boolean result = uit.isValidInput(contextStr, testName.getMethodName(), testValidatorType, testMaximumLength, true,errorList);
        assertFalse(result);
        assertEquals(1, errorList.size());
        assertEquals(validationEx, errorList.getError(contextStr));
        verify(errors, times(1)).addError(contextStr, validationEx);
        verify(spyStringRule, times(1)).addWhitelistPattern(TEST_PATTERN);
        verify(spyStringRule, times(1)).setAllowNull(true);
        verify(spyStringRule, times(0)).setAllowNull(false);
        verify(spyStringRule, times(1)).setMaximumLength(testMaximumLength);
        verify(spyStringRule, times(1)).setCanonicalize(true);
        verify(spyStringRule, times(1)).getValid(contextStr, testName.getMethodName());
    }
    
    @Test
    public void canonicalizeSettingPassedThrough() throws Exception {
        String safeValue =  uit.getValidInput(contextStr, testName.getMethodName(), testValidatorType, testMaximumLength, false,false);
        assertEquals(validatorResultString, safeValue);
        verify(spyStringRule, times(1)).addWhitelistPattern(TEST_PATTERN);
        verify(spyStringRule, times(0)).setAllowNull(true);
        verify(spyStringRule, times(1)).setAllowNull(false);
        verify(spyStringRule, times(1)).setMaximumLength(testMaximumLength);
        verify(spyStringRule, times(1)).setCanonicalize(false);
        verify(spyStringRule, times(1)).getValid(contextStr, testName.getMethodName());
    }
}
