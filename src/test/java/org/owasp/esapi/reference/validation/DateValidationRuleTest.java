package org.owasp.esapi.reference.validation;

import java.text.DateFormat;
import java.text.ParseException;
import java.util.Date;
import java.util.Locale;

import org.hamcrest.CustomMatcher;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.rules.TestName;
import org.mockito.Mockito;
import org.owasp.esapi.Encoder;
import org.owasp.esapi.errors.ValidationException;
import org.powermock.reflect.Whitebox;


public class DateValidationRuleTest {
    
    @Rule
    public ExpectedException exEx = ExpectedException.none();
    @Rule
    public TestName testName = new TestName();
    private ParseException testParseEx = new ParseException("Test Exception", 0);
    private Date testDate = new Date();
    private String fauxDateString = "I'm A Real Date!";
    private String canonDateString = "CanonDate";
  
    private String contextStr;
    private Encoder mockEncoder;
    private DateFormat testFormat = DateFormat.getDateInstance(DateFormat.MEDIUM, Locale.US);
    private DateValidationRule uit;
    
    @Before
    public void setup() {
        mockEncoder = Mockito.mock(Encoder.class);
        testFormat = Mockito.spy(testFormat);
        uit = new DateValidationRule(testName.getMethodName(), mockEncoder, testFormat);
        contextStr = testName.getMethodName();
    }
    @Test
    public void testCtrNullDateFormatThrows() {
        exEx.expect(IllegalArgumentException.class);
        exEx.expectMessage("DateValidationRule.setDateFormat requires a non-null DateFormat");
        new DateValidationRule("context", mockEncoder, null);
    }
    
    @Test
    public void testCtrSetDateFormat() {
        DateFormat uitFormat = Whitebox.getInternalState(uit, "format");
        Assert.assertEquals(testFormat, uitFormat);
    }
    @Test
    public void testsetDateFormatNullThrows() {
        exEx.expect(IllegalArgumentException.class);
        exEx.expectMessage("DateValidationRule.setDateFormat requires a non-null DateFormat");
        uit.setDateFormat(null);
    }
    
    @Test
    public void testsetDateFormat() {
        DateFormat newFormat = DateFormat.getDateInstance(DateFormat.SHORT, Locale.US);
        uit.setDateFormat(newFormat);
        DateFormat uitFormat = Whitebox.getInternalState(uit, "format");
        Assert.assertEquals(newFormat, uitFormat);
    }
    
    @Test
    public void testGetValidNullInputAllowed() throws ValidationException {
        uit.setAllowNull(true);
        Date vDate = uit.getValid(contextStr, null);
        Assert.assertNull(vDate);
    }
    
    @Test
    public void testGetValidNullInputNotAllowed() throws ValidationException {
        exEx.expect(ValidationException.class);
        exEx.expectMessage("Input date required");
        uit.setAllowNull(false);
        uit.getValid(contextStr, null);
    }
    
    @Test
    public void testGetValidNullInputNotAllowedEmptyString() throws ValidationException {
        exEx.expect(ValidationException.class);
        exEx.expectMessage("Input date required");
        uit.setAllowNull(false);
        uit.getValid(contextStr, "");
    }
    
    @Test
    public void testGetValidBadDateThrows() throws ValidationException, ParseException {
        exEx.expect(ValidationException.class);
        exEx.expectMessage(contextStr + ": Invalid date");
        exEx.expectCause(new CustomMatcher<Throwable>("Check for Test Parse Exception") {

            @Override
            public boolean matches(Object item) {
               return item.equals(testParseEx);
            }
        });
        
        Mockito.when(mockEncoder.canonicalize(fauxDateString)).thenReturn(canonDateString);
        Mockito.doThrow(testParseEx).when(testFormat).parse(canonDateString);
        
        uit.getValid(contextStr, fauxDateString);
    }
    
    @Test
    public void testGetValidHappyPath() throws ValidationException, ParseException {
        Mockito.when(mockEncoder.canonicalize(fauxDateString)).thenReturn(canonDateString);
        Mockito.doReturn(testDate).when(testFormat).parse(canonDateString);
        
        Date date = uit.getValid(contextStr, fauxDateString);
        Assert.assertEquals(testDate, date);
    }
    

    @Test
    public void testSanitizeNullInputAllowed() throws ValidationException {
        uit.setAllowNull(true);
        Date vDate = uit.sanitize(contextStr, null);
        Assert.assertNull(vDate);
    }
    
    @Test
    public void testSanitizeNullInputNotAllowed() throws ValidationException {
        uit.setAllowNull(false);
        Date date = uit.sanitize(contextStr, null);
        Assert.assertEquals(0, date.getTime());
    }
    
    @Test
    public void testSanitizeNullInputNotAllowedEmptyString() throws ValidationException {
        uit.setAllowNull(false);
        Date date = uit.sanitize(contextStr, "");
        Assert.assertEquals(0, date.getTime());
    }
    
    @Test
    public void testSanitizeBadDateReturnsDefault() throws ValidationException, ParseException {
        Mockito.when(mockEncoder.canonicalize(fauxDateString)).thenReturn(canonDateString);
        Mockito.doThrow(testParseEx).when(testFormat).parse(canonDateString);
        
        Date date =  uit.sanitize(contextStr, fauxDateString);
        Assert.assertEquals(0, date.getTime());
    }
    
    @Test
    public void testSanitizeHappyPath() throws ValidationException, ParseException {
        Mockito.when(mockEncoder.canonicalize(fauxDateString)).thenReturn(canonDateString);
        Mockito.doReturn(testDate).when(testFormat).parse(canonDateString);
        
        Date date = uit.sanitize(contextStr, fauxDateString);
        Assert.assertEquals(testDate, date);
    }
    
}
