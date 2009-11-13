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
package org.owasp.esapi.errors;

import org.owasp.esapi.errors.AccessControlException;
import org.owasp.esapi.errors.AuthenticationAccountsException;
import org.owasp.esapi.errors.AuthenticationCredentialsException;
import org.owasp.esapi.errors.AuthenticationException;
import org.owasp.esapi.errors.AuthenticationHostException;
import org.owasp.esapi.errors.AuthenticationLoginException;
import org.owasp.esapi.errors.AvailabilityException;
import org.owasp.esapi.errors.CertificateException;
import org.owasp.esapi.errors.EncodingException;
import org.owasp.esapi.errors.EncryptionException;
import org.owasp.esapi.errors.EnterpriseSecurityException;
import org.owasp.esapi.errors.ExecutorException;
import org.owasp.esapi.errors.IntegrityException;
import org.owasp.esapi.errors.IntrusionException;
import org.owasp.esapi.errors.ValidationAvailabilityException;
import org.owasp.esapi.errors.ValidationException;
import org.owasp.esapi.errors.ValidationUploadException;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * The Class AccessReferenceMapTest.
 * 
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 */
public class EnterpriseSecurityExceptionTest extends TestCase {
    
    /**
	 * Instantiates a new access reference map test.
	 * 
	 * @param testName
	 *            the test name
	 */
    public EnterpriseSecurityExceptionTest(String testName) {
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
        TestSuite suite = new TestSuite(EnterpriseSecurityExceptionTest.class);
        return suite;
    }

    
    /**
	 * Test of update method, of class org.owasp.esapi.AccessReferenceMap.
	 * 
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
    public void testExceptions() {
        System.out.println("exceptions");
        EnterpriseSecurityException e = null;
        e = new EnterpriseSecurityException();
        e = new EnterpriseSecurityException("m1","m2");
        e = new EnterpriseSecurityException("m1","m2",new Throwable());
        assertEquals( e.getUserMessage(), "m1" );
        assertEquals( e.getLogMessage(), "m2" );
        e = new AccessControlException();
        e = new AccessControlException("m1","m2");
        e = new AccessControlException("m1","m2",new Throwable());
        e = new AuthenticationException();
        e = new AuthenticationException("m1","m2");
        e = new AuthenticationException("m1","m2",new Throwable());
        e = new AvailabilityException();
        e = new AvailabilityException("m1","m2");
        e = new AvailabilityException("m1","m2",new Throwable());
        e = new CertificateException();
        e = new CertificateException("m1","m2");
        e = new CertificateException("m1","m2",new Throwable());
        e = new EncodingException();
        e = new EncodingException("m1","m2");
        e = new EncodingException("m1","m2",new Throwable());
        e = new EncryptionException();
        e = new EncryptionException("m1","m2");
        e = new EncryptionException("m1","m2",new Throwable());
        e = new ExecutorException();
        e = new ExecutorException("m1","m2");
        e = new ExecutorException("m1","m2",new Throwable());
        e = new ValidationException();
        e = new ValidationException("m1","m2");
        e = new ValidationException("m1","m2",new Throwable());
        e = new IntegrityException();
        e = new IntegrityException("m1","m2");
        e = new IntegrityException("m1","m2",new Throwable());
        e = new AuthenticationHostException();
        e = new AuthenticationHostException("m1","m2");
        e = new AuthenticationHostException("m1","m2",new Throwable());

        e = new AuthenticationAccountsException();
        e = new AuthenticationAccountsException("m1","m2");
        e = new AuthenticationAccountsException("m1","m2",new Throwable());
        e = new AuthenticationCredentialsException();
        e = new AuthenticationCredentialsException("m1","m2");
        e = new AuthenticationCredentialsException("m1","m2",new Throwable());
        e = new AuthenticationLoginException();
        e = new AuthenticationLoginException("m1","m2");
        e = new AuthenticationLoginException("m1","m2",new Throwable());
        e = new ValidationAvailabilityException();
        e = new ValidationAvailabilityException("m1","m2");
        e = new ValidationAvailabilityException("m1","m2",new Throwable());
        e = new ValidationUploadException();
        e = new ValidationUploadException("m1","m2");
        e = new ValidationUploadException("m1","m2",new Throwable());

        IntrusionException ex = new IntrusionException( "test", "test details");
        ex = new IntrusionException("m1","m2");
        ex = new IntrusionException("m1","m2", new Throwable());
        assertEquals( ex.getUserMessage(), "m1" );
        assertEquals( ex.getLogMessage(), "m2" );
    }
    
}
