package org.owasp.esapi.reference;


import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.powermock.api.mockito.PowerMockito.whenNew;

import java.text.DateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.Locale;

import org.hamcrest.core.Is;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.rules.TestName;
import org.junit.runner.RunWith;
import org.owasp.esapi.Encoder;
import org.owasp.esapi.ValidationErrorList;
import org.owasp.esapi.errors.IntrusionException;
import org.owasp.esapi.errors.ValidationException;
import org.owasp.esapi.reference.validation.DateValidationRule;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

/**
 * This class contains a subsection of tests of the DefaultValidator class 
 * SPECIFIC TO THE DATE VALIDATION API.
 * 
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest(DefaultValidator.class)
public class DefaultValidaterDateAPITest {
    @Rule
    public ExpectedException exEx = ExpectedException.none();
    @Rule
    public TestName testName = new TestName();
    private String dateString="Input Does not matter in this context";
    
    private ValidationException validationEx;
    private Date testDate = new Date();
    private String contextStr;
    private Encoder mockEncoder;
    private DateFormat testFormat = DateFormat.getDateInstance(DateFormat.MEDIUM, Locale.US);
    private DateValidationRule spyDateRule;
    private ValidationErrorList errors = new ValidationErrorList();
    
    private DefaultValidator uit;
    
    
    @Before
    public void setup() throws Exception {
        contextStr = testName.getMethodName();
        
        validationEx = new ValidationException(contextStr, contextStr);
        
        mockEncoder = mock(Encoder.class);
        uit = new DefaultValidator(mockEncoder);
        
        spyDateRule = new DateValidationRule(contextStr, mockEncoder, testFormat);
        spyDateRule = spy(spyDateRule);
        whenNew(DateValidationRule.class).withArguments(anyString(), eq(mockEncoder), eq(testFormat)).thenReturn(spyDateRule);
        
        errors = spy(errors);
        whenNew(ValidationErrorList.class).withNoArguments().thenReturn(errors);
    }
    
    @After
    public void tearDown() {
        verifyNoMoreInteractions(spyDateRule, errors);
    }
    
    @Test
    public void testIsValidDate() {
        doReturn(testDate).when(spyDateRule).sanitize(eq(contextStr), eq(dateString), isA(ValidationErrorList.class));
        
        boolean isValid = uit.isValidDate(contextStr, dateString, testFormat, true);
        Assert.assertTrue("Mock is configured to return a valid date, return should be equally valid.", isValid);
        
        verify(errors, atLeastOnce()).isEmpty();
        verify(errors, times(0)).errors();
        verify(spyDateRule, times(1)).setAllowNull(true);
        verify(spyDateRule, times(1)).sanitize(eq(contextStr), eq(dateString), isA(ValidationErrorList.class));
    }
    
    @Test
    public void testIsValidDateErrorList() {
        doReturn(testDate).when(spyDateRule).sanitize(eq(contextStr), eq(dateString), isA(ValidationErrorList.class));
        
        boolean isValid = uit.isValidDate(contextStr, dateString, testFormat, true, errors);
        Assert.assertTrue("Mock is configured to return a valid date, return should be equally valid.", isValid);
        
        verify(errors, atLeastOnce()).isEmpty();
        verify(errors, times(0)).errors();
        verify(spyDateRule, times(1)).setAllowNull(true);
        verify(spyDateRule, times(1)).sanitize(eq(contextStr), eq(dateString), eq(errors));
    }
    
    @Test
    public void testGetValidDate() throws IntrusionException, ValidationException {
        doReturn(testDate).when(spyDateRule).sanitize(eq(contextStr), eq(dateString), isA(ValidationErrorList.class));
        Date validDate = uit.getValidDate(contextStr, dateString, testFormat, true);
        Assert.assertEquals("ValidDate should match the mock's configured return value", testDate, validDate);
        
        verify(errors, atLeastOnce()).isEmpty();
        verify(errors, times(0)).errors();
        verify(spyDateRule, times(1)).setAllowNull(true);
        verify(spyDateRule, times(1)).sanitize(eq(contextStr), eq(dateString), isA(ValidationErrorList.class));
    }
    
    @Test
    public void testGetValidDateErrorList() {
        doReturn(testDate).when(spyDateRule).sanitize(eq(contextStr), eq(dateString), isA(ValidationErrorList.class));
        Date validDate = uit.getValidDate(contextStr, dateString, testFormat, true, errors);
        Assert.assertEquals("ValidDate should match the mock's configured return value", testDate, validDate);
        
        verify(errors, atLeastOnce()).isEmpty();
        verify(errors, times(0)).errors();
        verify(spyDateRule, times(1)).setAllowNull(true);
        verify(spyDateRule, times(1)).sanitize(eq(contextStr), eq(dateString), eq(errors));
    }
    
    
    @Test
    public void testIsValidDateOnValidationError() {
        doReturn(false).when(errors).isEmpty();
        doReturn(Arrays.asList(validationEx)).when(errors).errors();
        
        doReturn(testDate).when(spyDateRule).sanitize(eq(contextStr), eq(dateString), isA(ValidationErrorList.class));
        
        boolean isValid = uit.isValidDate(contextStr, dateString, testFormat, true);
        Assert.assertFalse("On ValidationException input should be invalid", isValid);
        
        verify(errors, atLeastOnce()).isEmpty();
        verify(errors, times(1)).errors();
        verify(spyDateRule, times(1)).setAllowNull(true);
        verify(spyDateRule, times(1)).sanitize(eq(contextStr), eq(dateString), isA(ValidationErrorList.class));
    }
    
    @Test
    public void testIsValidDateErrorListOnValidationError() {
        doReturn(false).when(errors).isEmpty();
        doReturn(Arrays.asList(validationEx)).when(errors).errors();
        
        doReturn(testDate).when(spyDateRule).sanitize(eq(contextStr), eq(dateString), isA(ValidationErrorList.class));
        
        boolean isValid = uit.isValidDate(contextStr, dateString, testFormat, true, errors);
        Assert.assertFalse("On ValidationException input should be invalid", isValid);
        
        verify(errors, times(2)).isEmpty();
        verify(errors, times(0)).errors();
        verify(spyDateRule, times(1)).setAllowNull(true);
        verify(spyDateRule, times(1)).sanitize(eq(contextStr), eq(dateString), eq(errors));
    }
    @Test
    public void testGetValidDateOnValidationError() throws IntrusionException, ValidationException {
        exEx.expect(Is.is(validationEx));
        doReturn(false).when(errors).isEmpty();
        doReturn(Arrays.asList(validationEx)).when(errors).errors();

        doReturn(testDate).when(spyDateRule).sanitize(eq(contextStr), eq(dateString), isA(ValidationErrorList.class));
        try {
            uit.getValidDate(contextStr, dateString, testFormat, true);
        } finally {
            verify(errors, atLeastOnce()).isEmpty();
            verify(errors, times(1)).errors();
            verify(spyDateRule, times(1)).setAllowNull(true);
            verify(spyDateRule, times(1)).sanitize(eq(contextStr), eq(dateString), isA(ValidationErrorList.class));
        }
    }
    
    @Test
    public void testGetValidDateErrorListOnValidationError() {
        doReturn(false).when(errors).isEmpty();
        doReturn(Arrays.asList(validationEx)).when(errors).errors();

        doReturn(testDate).when(spyDateRule).sanitize(eq(contextStr), eq(dateString), isA(ValidationErrorList.class));
        Date validDate = uit.getValidDate(contextStr, dateString, testFormat, true, errors);
        Assert.assertNull(validDate);
        verify(errors, atLeastOnce()).isEmpty();
        verify(errors, times(0)).errors();
        verify(spyDateRule, times(1)).setAllowNull(true);
        verify(spyDateRule, times(1)).sanitize(eq(contextStr), eq(dateString), isA(ValidationErrorList.class));
    }

}
