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
package org.owasp.esapi.reference;

import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.owasp.esapi.Authenticator;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.User;
import org.owasp.esapi.errors.AccessControlException;
import org.owasp.esapi.errors.AuthenticationException;
import org.owasp.esapi.errors.EncryptionException;


/**
 * The Class AccessReferenceMapTest.
 * 
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 */
public class IntegerAccessReferenceMapTest extends TestCase {
    
    /**
	 * Instantiates a new access reference map test.
	 * 
	 * @param testName
	 *            the test name
	 */
    public IntegerAccessReferenceMapTest(String testName) {
        super(testName);
    }

    /**
     * {@inheritDoc}
     */
    protected void setUp() throws Exception {
    	// none
    }

    /**
     * {@inheritDoc}
     */
    protected void tearDown() throws Exception {
    	// none
    }

    /**
	 * Suite.
	 * 
	 * @return the test
	 */
    public static Test suite() {
        TestSuite suite = new TestSuite(IntegerAccessReferenceMapTest.class);
        return suite;
    }

    
    /**
	 * Test of update method, of class org.owasp.esapi.AccessReferenceMap.
	 * 
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
    public void testUpdate() throws AuthenticationException, EncryptionException {
        System.out.println("update");
    	RandomAccessReferenceMap arm = new RandomAccessReferenceMap();
    	Authenticator auth = ESAPI.authenticator();
    	
    	String pass = auth.generateStrongPassword();
    	User u = auth.createUser( "armUpdate", pass, pass );
    	
    	// test to make sure update returns something
		arm.update(auth.getUserNames());
		String indirect = arm.getIndirectReference( u.getAccountName() );
		if ( indirect == null ) fail();
		
		// test to make sure update removes items that are no longer in the list
		auth.removeUser( u.getAccountName() );
		arm.update(auth.getUserNames());
		indirect = arm.getIndirectReference( u.getAccountName() );
		if ( indirect != null ) fail();
		
		// test to make sure old indirect reference is maintained after an update
		arm.update(auth.getUserNames());
		String newIndirect = arm.getIndirectReference( u.getAccountName() );
		assertEquals(indirect, newIndirect);
    }
    
    
    /**
	 * Test of iterator method, of class org.owasp.esapi.AccessReferenceMap.
	 */
    public void testIterator() {
        System.out.println("iterator");
    	RandomAccessReferenceMap arm = new RandomAccessReferenceMap();
        Authenticator auth = ESAPI.authenticator();
        
		arm.update(auth.getUserNames());

		Iterator i = arm.iterator();
		while ( i.hasNext() ) {
			String userName = (String)i.next();
			User u = auth.getUser( userName );
			if ( u == null ) fail();
		}
    }
    
    /**
	 * Test of getIndirectReference method, of class
	 * org.owasp.esapi.AccessReferenceMap.
	 */
    public void testGetIndirectReference() {
        System.out.println("getIndirectReference");
        
        String directReference = "234";
        Set list = new HashSet();
        list.add( "123" );
        list.add( directReference );
        list.add( "345" );
        RandomAccessReferenceMap instance = new RandomAccessReferenceMap( list );
        
        String expResult = directReference;
        String result = instance.getIndirectReference(directReference);
        assertNotSame(expResult, result);        
    }

    /**
	 * Test of getDirectReference method, of class
	 * org.owasp.esapi.AccessReferenceMap.
	 * 
	 * @throws AccessControlException
	 *             the access control exception
	 */
    public void testGetDirectReference() throws AccessControlException {
        System.out.println("getDirectReference");
        
        String directReference = "234";
        Set list = new HashSet();
        list.add( "123" );
        list.add( directReference );
        list.add( "345" );
        RandomAccessReferenceMap instance = new RandomAccessReferenceMap( list );
        
        String ind = instance.getIndirectReference(directReference);
        String dir = (String)instance.getDirectReference(ind);
        assertEquals(directReference, dir);
        try {
        	instance.getDirectReference("invalid");
        	fail();
        } catch( AccessControlException e ) {
        	// success
        }
    }
    
    public void testAddDirectReference() throws AccessControlException {
        System.out.println("addDirectReference");
        
        String directReference = "234";
        Set list = new HashSet();
        list.add( "123" );
        list.add( directReference );
        list.add( "345" );
        RandomAccessReferenceMap instance = new RandomAccessReferenceMap( list );
        
        String newDirect = instance.addDirectReference("newDirect");
        assertNotNull( newDirect );
        String ind = instance.addDirectReference(directReference);
        String dir = (String)instance.getDirectReference(ind);
        assertEquals(directReference, dir);
    	String newInd = instance.addDirectReference(directReference);
    	assertEquals(ind, newInd);
    }

    public void testRemoveDirectReference() throws AccessControlException {
        System.out.println("removeDirectReference");
        
        String directReference = "234";
        Set list = new HashSet();
        list.add( "123" );
        list.add( directReference );
        list.add( "345" );
        RandomAccessReferenceMap instance = new RandomAccessReferenceMap( list );
        
        String indirect = instance.getIndirectReference(directReference);
        assertNotNull(indirect);
        String deleted = instance.removeDirectReference(directReference);
        assertEquals(indirect,deleted);
    	deleted = instance.removeDirectReference("ridiculous");
    	assertNull(deleted);
    }
    
    
    
}
