package org.owasp.esapi.reference.validation;

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;

import org.hamcrest.CustomMatcher;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.rules.TestName;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Encoder;
import org.owasp.esapi.ValidationErrorList;
import org.owasp.esapi.errors.ValidationException;
import org.owasp.esapi.reference.DefaultSecurityConfiguration;
import org.powermock.reflect.Whitebox;


public class DateValidationRuleTest {
    
    @Rule
    public ExpectedException exEx = ExpectedException.none();
    @Rule
    public TestName testName = new TestName();
    private ParseException testParseEx = new ParseException("Test Exception", 0);
    private Date testDate = new Date();
    private String dateString;
    private String canonDateString ;
    
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
        
        dateString = testFormat.format(testDate);
        canonDateString = dateString;
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
        boolean acceptLenient = ESAPI.securityConfiguration().getBooleanProp( DefaultSecurityConfiguration.ACCEPT_LENIENT_DATES);
        DateFormat newFormat = DateFormat.getDateInstance(DateFormat.SHORT, Locale.US);
        newFormat.setLenient(!acceptLenient);
        
        newFormat = Mockito.spy(newFormat);
        
        uit.setDateFormat(newFormat);
        DateFormat uitFormat = Whitebox.getInternalState(uit, "format");
        Assert.assertEquals(newFormat, uitFormat);
        Mockito.verify(newFormat).setLenient(acceptLenient);
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
        
        Mockito.when(mockEncoder.canonicalize(dateString)).thenReturn(canonDateString);
        Mockito.doThrow(testParseEx).when(testFormat).parse(canonDateString);
        
        uit.getValid(contextStr, dateString);
    }
    
    @Test
    public void testGetValidHappyPath() throws ValidationException, ParseException {
        Mockito.when(mockEncoder.canonicalize(dateString)).thenReturn(canonDateString);
        Mockito.doReturn(testDate).when(testFormat).parse(canonDateString);
        
        Date date = uit.getValid(contextStr, dateString);
        Assert.assertEquals(testDate, date);
    }
    
    @Test
    public void testGetValidDateWithCruft() throws ValidationException, ParseException {
        String cruftyDate = canonDateString + "' union select * from another_table where user_id like '%";
        Mockito.when(mockEncoder.canonicalize(cruftyDate)).thenReturn(cruftyDate);
        Mockito.doReturn(testDate).when(testFormat).parse(cruftyDate);
        
        Date date = uit.getValid(contextStr, cruftyDate);
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
        Mockito.when(mockEncoder.canonicalize(dateString)).thenReturn(canonDateString);
        Mockito.doThrow(testParseEx).when(testFormat).parse(canonDateString);
        
        Date date =  uit.sanitize(contextStr, dateString);
        Assert.assertEquals(0, date.getTime());
    }
    
    @Test
    public void testSanitizeErrorListContainsError() throws ValidationException, ParseException {
        ValidationErrorList vel = new ValidationErrorList();
        Mockito.when(mockEncoder.canonicalize(dateString)).thenReturn(canonDateString);
        Mockito.doThrow(testParseEx).when(testFormat).parse(canonDateString);
        
        Date date =  uit.sanitize(contextStr, dateString, vel);
        Assert.assertEquals(0, date.getTime());
        Assert.assertEquals(1, vel.size());
        ValidationException wrapper = vel.errors().get(0);
        Assert.assertEquals(testParseEx, wrapper.getCause());
    }
    
    @Test
    public void testSanitizeHappyPath() throws ValidationException, ParseException {
        Mockito.when(mockEncoder.canonicalize(dateString)).thenReturn(canonDateString);
        Mockito.doReturn(testDate).when(testFormat).parse(canonDateString);
        
        Date date = uit.sanitize(contextStr, dateString);
        Assert.assertEquals(testDate, date);
    }
    @Test
    public void testSanitizeDateWithCruft() throws ValidationException, ParseException {
        String cruftyDate = canonDateString + "' union select * from another_table where user_id like '%";
        Mockito.when(mockEncoder.canonicalize(cruftyDate)).thenReturn(cruftyDate);
        Mockito.doReturn(testDate).when(testFormat).parse(cruftyDate);
        
        Date date = uit.sanitize(contextStr, cruftyDate);
        Assert.assertEquals(0, date.getTime());
    }
    
    @Test
    public void testGithubIssue299() throws ParseException, ValidationException {
        Map<DateFormat, String> formatDateMap = new HashMap<>();
        formatDateMap.put(new SimpleDateFormat("dd/MM/yyyy"), "01/01/2aaa");
        formatDateMap.put(new SimpleDateFormat("yyyy/dd/MM"), "2aaa/01/01");
        formatDateMap.put(new SimpleDateFormat("dd/yyyy/MM"), "01/2012'SELECT * FROM user_table'/01");
        formatDateMap.put(new SimpleDateFormat("dd/MM/yyyy"),"01/01/2012'SELECT * FROM user_table'");
        formatDateMap.put(new SimpleDateFormat("dd/yyyy/MM"),"01/2aaa/01");
        formatDateMap.put(SimpleDateFormat.getDateInstance(SimpleDateFormat.LONG, Locale.US), "September 11, 2001' union select * from another_table where user_id like '%");
        
        for (Entry<DateFormat, String> pair : formatDateMap.entrySet()) {
            String cruftyDate = pair.getValue();
            Mockito.when(mockEncoder.canonicalize(cruftyDate)).thenReturn(cruftyDate);
            
            DateFormat lenientFormat = Mockito.spy(pair.getKey());
            lenientFormat.setLenient(true);
            Mockito.doNothing().when(lenientFormat).setLenient(ArgumentMatchers.anyBoolean());
            Mockito.doReturn(testDate).when(lenientFormat).parse(cruftyDate);
            
            DateFormat strictFormat = Mockito.spy(pair.getKey());
            strictFormat.setLenient(false);
            Mockito.doNothing().when(strictFormat).setLenient(ArgumentMatchers.anyBoolean());
            Mockito.doReturn(testDate).when(strictFormat).parse(cruftyDate);
            
            uit.setDateFormat(lenientFormat);
            Date lenientValidDate = uit.getValid(contextStr, cruftyDate);
            Assert.assertEquals("calls to getValid should not change the parsed date regardless of cruft",testDate, lenientValidDate);
            Date lenientSanitizedDate = uit.sanitize(contextStr, cruftyDate);
            Assert.assertEquals("calls to sanitize should return default date if cruft exists in input string",0, lenientSanitizedDate.getTime());
            
            uit.setDateFormat(strictFormat);
            Date strictValidDate = uit.getValid(contextStr, cruftyDate);
            Assert.assertEquals("calls to getValid should not change the parsed date regardless of cruft",testDate, strictValidDate);
            Date strictSanitizedDate = uit.sanitize(contextStr, cruftyDate);
            Assert.assertEquals("calls to sanitize should return default date if cruft exists in input string",0, strictSanitizedDate.getTime());
        }
    }
}
