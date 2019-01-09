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
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2007
 */
package org.owasp.esapi;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.rules.TestName;
import org.owasp.esapi.errors.ValidationException;


/**
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 */
public class ValidationErrorListTest {
    @Rule
    public ExpectedException exEx = ExpectedException.none();
    @Rule
    public TestName testName = new TestName();

    ValidationErrorList vel = new ValidationErrorList();
    ValidationException vex = new ValidationException(testName.getMethodName(), testName.getMethodName());
    @Test
    public void testAddErrorNullContextThrows() {
        exEx.expect(RuntimeException.class);
        exEx.expectMessage("Context cannot be null");
        vel.addError(null, vex);
    }

    @Test
    public void testAddErrorNullExceptionThrows() {
        exEx.expect(RuntimeException.class);
        exEx.expectMessage("ValidationException cannot be null");
        vel.addError(testName.getMethodName(), null);
    }
    public void testAddErrorDuplicateContextThrows() {
        exEx.expect(RuntimeException.class);
        exEx.expectMessage("already exists, must be unique");
        vel.addError(testName.getMethodName(), vex);
        vel.addError(testName.getMethodName(), vex);
    }

    @Test
    public void testErrors() throws Exception {
        vel.addError("context",  vex );
        assertTrue("Validation Errors List should contain the added ValidationException Reference",vel.errors().contains( vex) );
    }

    @Test
    public void testGetError() throws Exception {
        vel.addError("context",  vex );
        assertTrue( vel.getError( "context" ) == vex );
        assertNull( vel.getError( "ridiculous" ) );
    }

    @Test
    public void testIsEmpty() throws Exception {
        assertTrue( vel.isEmpty() );
        vel.addError("context",  vex );
        assertFalse( vel.isEmpty() );
    }

    @Test
    public void testSize() throws Exception {
        assertEquals(0, vel.size() );
        vel.addError("context",  vex );
        assertEquals(1, vel.size());
    }

}


