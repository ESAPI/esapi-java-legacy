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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;
import org.owasp.esapi.errors.IntrusionException;
import org.owasp.esapi.errors.ValidationException;


/**
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 */
public class ValidationErrorListTest {

	@Test	
	public void testAddError() throws Exception {
		System.out.println("testAddError");
		ValidationErrorList vel = new ValidationErrorList();
		ValidationException vex = createValidationException();
		vel.addError("context", vex );
		try {
			vel.addError(null, vex );
			fail();
		} catch( Exception e ) {
			// expected
		}
		try {
			vel.addError("context1", null );
			fail();
		} catch( Exception e ) {
			// expected
		}
		try {
			vel.addError("context", vex );  // add the same context again
			fail();
		} catch( Exception e ) {
			// expected
		}
	}
	
	@Test
	public void testErrors() throws Exception {
		System.out.println("testErrors");
		ValidationErrorList vel = new ValidationErrorList();
		ValidationException vex = createValidationException();
		vel.addError("context",  vex );
		assertTrue( vel.errors().get(0) == vex );
	}

	@Test
	public void testGetError() throws Exception {
		System.out.println("testGetError");
		ValidationErrorList vel = new ValidationErrorList();
		ValidationException vex = createValidationException();
		vel.addError("context",  vex );
		assertTrue( vel.getError( "context" ) == vex );
		assertTrue( vel.getError( "ridiculous" ) == null );
	}

	@Test
	public void testIsEmpty() throws Exception {
		System.out.println("testIsEmpty");
		ValidationErrorList vel = new ValidationErrorList();
		assertTrue( vel.isEmpty() );
		ValidationException vex = createValidationException();
		vel.addError("context",  vex );
		assertFalse( vel.isEmpty() );
	}

	@Test
	public void testSize() throws Exception {
		System.out.println("testSize");
		ValidationErrorList vel = new ValidationErrorList();
		assertTrue( vel.size() == 0 );
		ValidationException vex = createValidationException();
		vel.addError("context",  vex );
		assertTrue( vel.size() == 1 );
	}

	private ValidationException createValidationException() {
		ValidationException vex = null;
		try {
			vex = new ValidationException("User message", "Log Message");
		} catch( IntrusionException e ) {
			// expected occasionally
		}
		return vex;
	}
	
}


