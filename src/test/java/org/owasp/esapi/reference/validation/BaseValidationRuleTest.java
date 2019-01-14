/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Ben Sleek <a href="http://www.spartasystems.com">Sparta Systems</a>
 * @created 2015
 */
package org.owasp.esapi.reference.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.hamcrest.Matcher;
import org.hamcrest.core.Is;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.owasp.esapi.Encoder;
import org.owasp.esapi.ValidationErrorList;
import org.owasp.esapi.errors.ValidationException;

public class BaseValidationRuleTest {
    /**Static Test Data.*/
    private static final String STR_VAL="";
    private static final String EX_MSG="Expected Failure Message from " + BaseValidationRuleTest.class.getSimpleName();
    @Rule
    public ExpectedException exEx = ExpectedException.none();

    private ValidationException testValidationEx = new ValidationException(EX_MSG, EX_MSG);

    private BaseValidationRule uit = mock(BaseValidationRule.class, CALLS_REAL_METHODS);
    @Test
    public void testCtrNullTypeName() throws Exception { 
        String typename = null;
        BaseValidationRule rule = mock(BaseValidationRule.class, withSettings()
                .useConstructor(typename)
                .defaultAnswer(CALLS_REAL_METHODS)
                );
        assertNull(rule.getTypeName());
    }

    @Test
    public void testCtrNullEncoder() {
        String typename = "typename";
        Encoder encoder = null;
        BaseValidationRule rule = mock(BaseValidationRule.class, withSettings()
                .useConstructor(typename, encoder)
                .defaultAnswer(CALLS_REAL_METHODS)
                );
        assertEquals(typename, rule.getTypeName());
        assertNull(rule.getEncoder());
    }
    
    @Test
    public void testCtrNullTypenameNullEncoder() {
        String typename = null;
        Encoder encoder = null;
        BaseValidationRule rule = mock(BaseValidationRule.class, withSettings()
                .useConstructor(typename, encoder)
                .defaultAnswer(CALLS_REAL_METHODS)
                );
        assertNull(rule.getTypeName());
        assertNull(rule.getEncoder());
    }

    @Test
    public void testCtr2ArgHappyPath() {
        String typename = "typename";
        Encoder encoder = mock(Encoder.class);
        BaseValidationRule rule =  mock(BaseValidationRule.class, withSettings()
                .useConstructor(typename, encoder)
                .defaultAnswer(CALLS_REAL_METHODS)
                );
        assertEquals(typename, rule.getTypeName());
        assertEquals(encoder, rule.getEncoder());
    }

    @Test
    public void testCtr1ArgHappyPath() {
        String typename = "typename";
        mock(BaseValidationRule.class, withSettings()
                .useConstructor(typename)
                .defaultAnswer(CALLS_REAL_METHODS)
                );
    }

    @Test
    public void testSetTypeNameNull() {
        uit.setTypeName(null); 
        assertNull(uit.getTypeName());
    }

    @Test
    public void testSetTypeName() {
        uit.setTypeName(STR_VAL);
        assertEquals(STR_VAL, uit.getTypeName());
    }

    @Test
    public void testSetEncoderNull() {
        uit.setEncoder(null);
        assertNull(uit.getEncoder());
    }

    @Test
    public void testSetEncoder() {
        Encoder mockEnc = mock(Encoder.class);
        uit.setEncoder(mockEnc);
        assertEquals(mockEnc, uit.getEncoder());
    }

    @Test
    public void testSetAllowNull() {
        uit.setAllowNull(true);
        assertTrue(uit.isAllowNull());
        uit.setAllowNull(false);
        assertFalse(uit.isAllowNull());
    }

    @Test
    public void testAssertValidCallsGetValid() throws ValidationException {
        when(uit.getValid(STR_VAL, STR_VAL)).thenReturn(this);
        uit.assertValid(STR_VAL, STR_VAL);
        verify(uit, times(1)).getValid(STR_VAL, STR_VAL);
    }
    @Test
    public void testAssertValidThrowsValidationException() throws ValidationException {
        /*
         * Verifies assertValid throws ValidationException on invalid input
         * Validates fix for Google issue #195
         */
        Matcher<ValidationException> validationExMatch = Is.is(testValidationEx);
        exEx.expect(validationExMatch);
        when(uit.getValid(STR_VAL, STR_VAL)).thenThrow(testValidationEx);
        uit.assertValid(STR_VAL, STR_VAL);
    }

    @Test
    public void testGetValidErrorListCallsGetValid() throws ValidationException {
        ValidationErrorList vel = new ValidationErrorList();
        when(uit.getValid(STR_VAL, STR_VAL)).thenReturn(this);
        Object vRef = uit.getValid(STR_VAL, STR_VAL, vel);
        assertEquals(this, vRef);
        verify(uit, times(1)).getValid(STR_VAL, STR_VAL);
    }

    @Test
    public void testGetValidExceptionAddedToErrorList() throws ValidationException {
        ValidationErrorList vel = new ValidationErrorList();
        when(uit.getValid(STR_VAL, STR_VAL)).thenThrow(testValidationEx);
        Object vRef = uit.getValid(STR_VAL, STR_VAL, vel);
        assertNull(vRef);
        List<ValidationException> elEx = vel.errors();
        assertEquals(1, elEx.size());
        assertEquals(testValidationEx, elEx.get(0));
        verify(uit, times(1)).getValid(STR_VAL, STR_VAL);
    }
    @Test
    public void testGetValidNullErrorListThrows() throws ValidationException {
        Matcher<ValidationException> validationExMatch = Is.is(testValidationEx);
        exEx.expect(validationExMatch);
        ValidationErrorList vel = null;
        when(uit.getValid(STR_VAL, STR_VAL)).thenThrow(testValidationEx);
        uit.getValid(STR_VAL, STR_VAL, vel);
    }

    @Test
    public void testGetSafeCallsGetValid() throws ValidationException {
        when(uit.getValid(STR_VAL, STR_VAL)).thenReturn(this);
        Object vRef = uit.getSafe(STR_VAL, STR_VAL);
        assertEquals(this, vRef);
        verify(uit, times(1)).getValid(STR_VAL, STR_VAL);
    }

    @Test
    public void testGetSafeOnExceptionCallsSanitize() throws ValidationException {
        when(uit.getValid(STR_VAL, STR_VAL)).thenThrow(testValidationEx);
        when(uit.sanitize(STR_VAL, STR_VAL)).thenReturn(this);
        Object vRef = uit.getSafe(STR_VAL, STR_VAL);
        assertEquals(this, vRef);
        verify(uit, times(1)).getValid(STR_VAL, STR_VAL);
        verify(uit, times(1)).sanitize(STR_VAL, STR_VAL);
    }

    @Test
    public void testIsValidCallsGetValid() throws ValidationException {
        when(uit.getValid(STR_VAL, STR_VAL)).thenReturn(this);
        assertTrue(uit.isValid(STR_VAL, STR_VAL));
        verify(uit, times(1)).getValid(STR_VAL, STR_VAL);
    }

    @Test
    public void testIsValidOnExceptionRetursFalse() throws ValidationException {
        when(uit.getValid(STR_VAL, STR_VAL)).thenThrow(testValidationEx);
        assertFalse(uit.isValid(STR_VAL, STR_VAL));
        verify(uit, times(1)).getValid(STR_VAL, STR_VAL);
    }

    /* *************************
     * TO DISCUSS 
     * FIXME
     * Tests below this block are items which are valid against the current implementation, but have side effects
     * or unclear results under certain conditions.
     * 
     * Once Items are discussed and understood they should probably be well-commented and moved out of this area.
     */

    @Test
    public void testGetValidMultipleExceptionSameContextThrowsRuntimeException() throws ValidationException {
        exEx.expect(RuntimeException.class);
        ValidationErrorList vel = new ValidationErrorList();
        when(uit.getValid(STR_VAL, STR_VAL)).thenThrow(testValidationEx);
        uit.getValid(STR_VAL, STR_VAL, vel);
        /*
         * Side-effect of ValidationErrorList. If the same context is used against a BaseValidationRule multiple times resulting in exception, the ValidationErrorList impl will blow up.
         * This can be an unclear event at runtime if a single BaseValidationRule instance is shared in an application and multiple parts happen to use the same contextual string to capture failure events.
         * 
         */
        uit.getValid(STR_VAL, STR_VAL, vel);
    }

    //None of the Whitelist content belongs in this class, IMO.
    
    @Test
    public void testWhitelistCharArrayCleansString() {
        String myString = "AAAGaaadBBB12345*";
        char[] whitelist = new char[] {'d', 'G', '3', '*', ']'};
        String result = uit.whitelist(myString, whitelist);
        assertEquals("Gd3*", result);
    }

    @Test
    public void testWhitelistNullCharArrayThrows() {
        exEx.expect(NullPointerException.class);
        String myString = "AAAGaaadBBB12345*";
        char[] whitelist = null;
        uit.whitelist(myString, whitelist);
    }

    @Test
    public void testWhitelistSetCleansString() {
        String myString = "AAAGaaadBBB12345*";
        Set<Character> whitelist = new HashSet<>();
        whitelist.add('d');
        whitelist.add('G');
        whitelist.add('3');
        whitelist.add('*');
        whitelist.add(']');
        String result = uit.whitelist(myString, whitelist);
        assertEquals("Gd3*", result);
    }

    @Test
    public void testWhitelistNullSetThrows() {
        exEx.expect(NullPointerException.class);
        String myString = "AAAGaaadBBB12345*";
        Set<Character> whitelist = null;
        uit.whitelist(myString, whitelist);
    }

    @Test
    
    public void testWhitelistSetExtendedCharacterSets() {
        String myString = "𡘾𦴩<𥻂";
        //(55365 56894) (55387 56617) 60 (55383 57026)
        Set<Character> whitelist = new HashSet<>();
        whitelist.add((char) 60);
        whitelist.add((char) 55387);
        whitelist.add((char) 56617);
        String result = uit.whitelist(myString, whitelist);
        assertEquals("𦴩<", result);
    }
}
