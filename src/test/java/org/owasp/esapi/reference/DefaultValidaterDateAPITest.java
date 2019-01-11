package org.owasp.esapi.reference;


import java.text.DateFormat;
import java.util.Date;
import java.util.Locale;

import org.junit.Before;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.rules.TestName;
import org.mockito.Mockito;
import org.owasp.esapi.Encoder;
import org.owasp.esapi.reference.validation.DateValidationRule;

/**
 * This class contains a subsection of tests of the DefaultValidator class 
 * SPECIFIC TO THE DATE VALIDATION API.
 * 
 */
@Ignore
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
    private DefaultValidator uit;
    
    
    @Before
    public void setup() {
        contextStr = testName.getMethodName();        
        
        mockEncoder = Mockito.mock(Encoder.class);
        uit = new DefaultValidator(mockEncoder);
        
        spyDateRule = new DateValidationRule(contextStr, mockEncoder, testFormat);
        spyDateRule = Mockito.spy(spyDateRule);
        
        //FIXME:  Argument Matchers for all to allow any ValidationErrorList
        Mockito.doReturn(testDate).when(spyDateRule).sanitize(contextStr, dateString, null);
        
        //FIXME:  when DateValidationRule ctr is called, return spyDateRule!
    }
    
    @Test
    public void testIsValidDate() {
        uit.isValidDate(contextStr, dateString, testFormat, true);
        
        Mockito.verify(spyDateRule, Mockito.times(1)).setAllowNull(true);
        Mockito.verify(spyDateRule, Mockito.times(1)).sanitize(contextStr, dateString, null);
    }
    
    @Test
    public void testIsValidDateErrorList() {
    
    }
    
    @Test
    public void testGetValidDate() {
    
    }
    
    @Test
    public void testGetValidDateErrorList() {
    
    }
}
