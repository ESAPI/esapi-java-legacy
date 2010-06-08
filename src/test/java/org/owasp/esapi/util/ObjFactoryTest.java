package org.owasp.esapi.util;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import java.security.Key;

import javax.crypto.spec.SecretKeySpec;

import org.owasp.esapi.errors.ConfigurationException;

public class ObjFactoryTest extends TestCase {
	
	// Purpose of this is to prevent a default, no-arg, public CTOR to be generated.
	// We want to prevent this so we can use this class to test the case of where
	// ObjectFactory<T>.make() throws an IllegalAccessException.
	@SuppressWarnings("unused")
	private ObjFactoryTest(int i) { ; }
	
    /**
	 * Instantiates a new object factory test.
	 * 
	 * @param testName
	 *            the test name
	 */
    public ObjFactoryTest(String testName) {
        super(testName);
    }

    /**
     * {@inheritDoc}
     * @throws Exception
     */
    protected void setUp() throws Exception {
    	// none
    }

    /**
     * {@inheritDoc}
     * @throws Exception
     */
    protected void tearDown() throws Exception {
    	// none
    }

    /**
	 * Run all the test cases in this suite.
     * This is to allow running from {@code org.owasp.esapi.AllTests}.
	 * 
	 * @return the test
	 */
    public static Test suite() {
        TestSuite suite = new TestSuite(ObjFactoryTest.class);
        return suite;
    }
    
    /** Test that NullCipher object is correctly returned. */
    public void testMakeNullCipher() throws ConfigurationException {
    	String className = "javax.crypto.NullCipher";
    	javax.crypto.Cipher nullCipher =
    			ObjFactory.make(className, "NullCipher");
    	assertTrue( nullCipher instanceof javax.crypto.NullCipher );
    	System.out.println("W00t! Watch out NSA...we have a NullCipher and we're not afraid to use it!");
    }
    
    /** Test that InstantiationException is thrown as the root cause when the
     * specified class name is an abstract class or interface.
     */
    public void testInterface() throws ConfigurationException {
    	Key key = null;  	
    	try {
    		key = ObjFactory.make("java.security.Key", "Key");
    		assertFalse("Should not be reached - interface or abstract class", key != null);
    	} catch(ConfigurationException ex) {
    		Throwable cause = ex.getCause();
    		assertTrue( cause instanceof InstantiationException);
    	}
    }
    
    /** Test that IllegalAccessException is thrown as the root cause when the
     *  specified class has no public, no-arg CTOR. Cipher has only a protected
     *  CTOR that takes multiple parameters.
     *  
     *  FIXME: Need new test. This also throws an InstantiationException as the
     *  root cause. The goal is to have it throw IllegalAccessException.
     */
    public void testMakeNoPublicConstructor() throws ConfigurationException {
    	ObjFactoryTest oft = null;	
    	try {
    		// CHECKME: As I read
			//	  http://java.sun.com/docs/books/tutorial/reflect/member/ctorTrouble.html
    		// this should cause an IllegalAccessException to be thrown because it has no public,
    		// no-arg CTOR. However, it doesn't. It throws a InstantiationException instead.
    		oft = ObjFactory.make(ObjFactoryTest.class.getName(), "ObjectFactoryTest");
    		assertFalse("Should not be reached - no public CTOR", oft != null);
    	} catch(ConfigurationException ex) {
    		Throwable cause = ex.getCause();
    		// assertTrue( cause instanceof IllegalAccessException);
    		assertTrue( cause instanceof InstantiationException);
    	}
    }
    
    /** Test that ClassNotFoundException is thrown as the root cause when
     * the class name to be created is not a class name that exists anywhere.
     */
    public void testMakeNoSuchClass() throws ConfigurationException {
    	Object obj = null;
    	
    	try {
    		obj = ObjFactory.make("kevin.wall.HasNoClass", "Object");
    		assertFalse("Should not be reached - no such class", obj != null);
    	} catch(ConfigurationException ex) {
    		Throwable cause = ex.getCause();
    		assertTrue( cause instanceof ClassNotFoundException);
    	}
    }
    
    /** Test that ClassCastException is thrown as the root cause when the
     * created class is not a subclass / does not implement the specified type.
     * (In this case, String is not a subclass / does not implement Key.)
     */
    public void testMakeNotASubclass() throws ConfigurationException {
    	Key key = null;
    	try {
    		key = ObjFactory.make("java.lang.String", "testMakeNotASubclass");
    		assertFalse("Should not be reached - not a subclass", key != null);
    	} catch(ConfigurationException ex) {
    		Throwable cause = ex.getCause();
    		System.out.println("DEBUG: Cause was: " + cause.getClass().getName());
    		assertTrue( cause instanceof ClassCastException);
    	} catch(ClassCastException ccex) {
    		assertTrue("Caught expected class cast exception", true);
    	}
    }
    
    /** Test that IllegalArgumentException is thrown as the cause when the
     * class name is specified as an empty string.
     */
    public void testMakeEmptyClassName() throws ConfigurationException {
    	Object obj = null;
    	try {
    		obj = ObjFactory.make("", "testMakeEmptyClassName");
    		assertFalse("Should not be reached - not a subclass", obj != null);
    	} catch(ConfigurationException ex) {
    		Throwable cause = ex.getCause();
    		assertTrue( cause instanceof IllegalArgumentException);
    	}
    }
    
    /** Test that some other exception is thrown from the no-arg, public CTOR as the
     * root cause. Had to use special external class here because strangely, this didn't
     * work as an inner class. (Threw InstantiationException in that case instead.)
     */
    public void testMakeOtherException() throws ConfigurationException {
    	@SuppressWarnings("unused")
		ThePrefectClass ford = null;
    	try {
    		ford = ObjFactory.make("org.owasp.esapi.util.ThePrefectClass", "ThePrefectClass");
    	} catch(ConfigurationException ex) {
    		Throwable cause = ex.getCause();
			assertTrue( cause instanceof UnsupportedOperationException);
    	}
    }
    
    /** Test case where typeName is null or empty string. */
    public void testNullorEmptyTypeName() throws ConfigurationException {
    	String className = "javax.crypto.NullCipher";
    	javax.crypto.Cipher nullCipher =
    			ObjFactory.make(className, null);
    	assertTrue( nullCipher instanceof javax.crypto.NullCipher );
    	nullCipher =
			ObjFactory.make(className, "");
    	assertTrue( nullCipher instanceof javax.crypto.NullCipher );
    }
    
    /** Test case where no-arg CTOR does not exist. By all indications from
     * Javadoc for {@code Class.newInstance()} one would think this should
     * throw an {@code IllegalAccessException} because {@code SecretKeySpec}
     * has two public CTORs that both take arguments. */
    public void testMakeCipher() throws ConfigurationException {
    	try {
    		String className = "javax.crypto.spec.SecretKeySpec";
    		javax.crypto.spec.SecretKeySpec skeySpec =
    			(SecretKeySpec) ObjFactory.make(className, "SecretKeySpec");
    		assertTrue( skeySpec != null );
    	} catch(ConfigurationException ex) {
    		Throwable cause = ex.getCause();
    		assertTrue( cause instanceof InstantiationException);
    	}
    }
}
