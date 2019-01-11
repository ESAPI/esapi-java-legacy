package org.owasp.esapi.reference;


import java.text.DateFormat;
import java.util.Date;
import java.util.Locale;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.rules.TestName;
import org.junit.runner.RunWith;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.owasp.esapi.Encoder;
import org.owasp.esapi.ValidationErrorList;
import org.owasp.esapi.errors.IntrusionException;
import org.owasp.esapi.errors.ValidationException;
import org.owasp.esapi.reference.validation.DateValidationRule;
import org.powermock.api.mockito.PowerMockito;
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
        
        mockEncoder = Mockito.mock(Encoder.class);
        uit = new DefaultValidator(mockEncoder);
        
        spyDateRule = new DateValidationRule(contextStr, mockEncoder, testFormat);
        spyDateRule = Mockito.spy(spyDateRule);
        
        
        PowerMockito.whenNew(DateValidationRule.class).withArguments(ArgumentMatchers.anyString(), ArgumentMatchers.eq(mockEncoder), ArgumentMatchers.eq(testFormat)).thenReturn(spyDateRule);
    }
    
    @After
    public void tearDown() {
        Mockito.verifyNoMoreInteractions(spyDateRule);
    }
    
    @Test
    public void testIsValidDate() {
        Mockito.doReturn(testDate).when(spyDateRule).sanitize(ArgumentMatchers.eq(contextStr), ArgumentMatchers.eq(dateString), ArgumentMatchers.isA(ValidationErrorList.class));
        
        boolean isValid = uit.isValidDate(contextStr, dateString, testFormat, true);
        Assert.assertTrue("Mock is configured to return a valid date, return should be equally valid.", isValid);
        
        Mockito.verify(spyDateRule, Mockito.times(1)).setAllowNull(true);
        Mockito.verify(spyDateRule, Mockito.times(1)).sanitize(ArgumentMatchers.eq(contextStr), ArgumentMatchers.eq(dateString), ArgumentMatchers.isA(ValidationErrorList.class));
    }
    
    @Test
    public void testIsValidDateErrorList() {
        Mockito.doReturn(testDate).when(spyDateRule).sanitize(ArgumentMatchers.eq(contextStr), ArgumentMatchers.eq(dateString), ArgumentMatchers.isA(ValidationErrorList.class));
        
        boolean isValid = uit.isValidDate(contextStr, dateString, testFormat, true, errors);
        Assert.assertTrue("Mock is configured to return a valid date, return should be equally valid.", isValid);
        
        Mockito.verify(spyDateRule, Mockito.times(1)).setAllowNull(true);
        Mockito.verify(spyDateRule, Mockito.times(1)).sanitize(ArgumentMatchers.eq(contextStr), ArgumentMatchers.eq(dateString), ArgumentMatchers.eq(errors));
    }
    
    @Test
    public void testGetValidDate() throws IntrusionException, ValidationException {
        Mockito.doReturn(testDate).when(spyDateRule).sanitize(ArgumentMatchers.eq(contextStr), ArgumentMatchers.eq(dateString), ArgumentMatchers.isA(ValidationErrorList.class));
        Date validDate = uit.getValidDate(contextStr, dateString, testFormat, true);
        Assert.assertEquals("ValidDate should match the mock's configured return value", testDate, validDate);
        
        Mockito.verify(spyDateRule, Mockito.times(1)).setAllowNull(true);
        Mockito.verify(spyDateRule, Mockito.times(1)).sanitize(ArgumentMatchers.eq(contextStr), ArgumentMatchers.eq(dateString), ArgumentMatchers.isA(ValidationErrorList.class));
    }
    
    @Test
    public void testGetValidDateErrorList() {
        Mockito.doReturn(testDate).when(spyDateRule).sanitize(ArgumentMatchers.eq(contextStr), ArgumentMatchers.eq(dateString), ArgumentMatchers.isA(ValidationErrorList.class));
        Date validDate = uit.getValidDate(contextStr, dateString, testFormat, true, errors);
        Assert.assertEquals("ValidDate should match the mock's configured return value", testDate, validDate);
        Mockito.verify(spyDateRule, Mockito.times(1)).setAllowNull(true);
        Mockito.verify(spyDateRule, Mockito.times(1)).sanitize(ArgumentMatchers.eq(contextStr), ArgumentMatchers.eq(dateString), ArgumentMatchers.eq(errors));
    }
}
