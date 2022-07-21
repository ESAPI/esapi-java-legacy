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
package org.owasp.esapi.reference.crypto;

import static org.junit.Assert.*;

import java.io.*;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Properties;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.owasp.esapi.errors.EncryptionException;
import org.owasp.esapi.errors.EncryptionRuntimeException;

/**
 * The Class EncryptedPropertiesTest.
 *
 * @author August Detlefsen (augustd at codemagi dot com)
 *         <a href="http://www.codemagi.com">CodeMagi, Inc.</a>
 * @since October 8, 2010
 */
public class ReferenceEncryptedPropertiesTest {

    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();

    /**
     * Test of getProperty method, of class org.owasp.esapi.EncryptedProperties.
     *
     * @throws EncryptionException
     *             the encryption exception
     */
    @Test public void testGetProperty() throws EncryptionException {
        System.out.println("getProperty");
        ReferenceEncryptedProperties instance = new ReferenceEncryptedProperties();
        String name = "name";
        String value = "value";
        instance.setProperty(name, value);
        String result = instance.getProperty(name);
        assertEquals(value, result);
        assertNull(instance.getProperty("ridiculous"));
    }

    /**
     * Test of setProperty method, of class org.owasp.esapi.EncryptedProperties.
     *
     * @throws EncryptionException
     *             the encryption exception
     */
    @Test public void testSetProperty() throws EncryptionException {
        System.out.println("setProperty");
        ReferenceEncryptedProperties instance = new ReferenceEncryptedProperties();
        String name = "name";
        String value = "value";
        instance.setProperty(name, value);
        String result = instance.getProperty(name);
        assertEquals(value, result);

        instance.setProperty(name, "");
        result = instance.getProperty(name);
        assertEquals(result, "");

        try {
            instance.setProperty(null, value);
            fail("testSetProperty(): Null property name did not result in expected exception.");
        } catch( Exception e ) {
            assertTrue( e instanceof EncryptionRuntimeException );
        }
        try {
            instance.setProperty(name, null);
            fail("testSetProperty(): Null property value did not result in expected exception.");
        } catch( Exception e ) {
            assertTrue( e instanceof EncryptionRuntimeException );
        }
        try {
            instance.setProperty(null, null);
            fail("testSetProperty(): Null property name and valud did not result in expected exception.");
        } catch( Exception e ) {
            assertTrue( e instanceof EncryptionRuntimeException );
        }
    }

    /**
     * Test the behavior when the requested key does not exist.
     */
    @Test public void testNonExistantKeyValue() throws Exception
    {
        ReferenceEncryptedProperties instance = new ReferenceEncryptedProperties();
        assertNull(instance.getProperty("not.there"));
    }

    /**
     * Test of keySet method, of class org.owasp.esapi.EncryptedProperties.
     */
    @Test public void testKeySet() throws Exception
    {
        boolean sawTwo = false;
        boolean sawOne = false;

        System.out.println("keySet");
        ReferenceEncryptedProperties instance = new ReferenceEncryptedProperties();
        instance.setProperty("one", "two");
        instance.setProperty("two", "three");
        Iterator i = instance.keySet().iterator();
        while(i.hasNext())
        {
            String key = (String)i.next();

            assertNotNull("key returned from keySet() iterator was null", key);
            if(key.equals("one"))
                if(sawOne)
                    fail("Key one seen more than once.");
                else
                    sawOne = true;
            else if(key.equals("two"))
                if(sawTwo)
                    fail("Key two seen more than once.");
                else
                    sawTwo = true;
            else
                fail("Unset key " + key + " returned from keySet().iterator()");
        }
        assertTrue("Key one was never seen", sawOne);
        assertTrue("Key two was never seen", sawTwo);
    }

    /**
     * Test storing and loading of encrypted properties.
     */
    @Test public void testStoreLoad() throws Exception
    {
        ReferenceEncryptedProperties toLoad = new ReferenceEncryptedProperties();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ByteArrayInputStream bais;
        boolean sawOne = false;
        boolean sawTwo = false;
        boolean sawSeuss = false;

        ReferenceEncryptedProperties toStore = new ReferenceEncryptedProperties();
        toStore.setProperty("one", "two");
        toStore.setProperty("two", "three");
        toStore.setProperty("seuss.schneier", "one fish, twofish, red fish, blowfish");
        toStore.store(baos, "testStore");

        bais = new ByteArrayInputStream(baos.toByteArray());
        toLoad.load(bais);

        for(Iterator i=toLoad.keySet().iterator();i.hasNext();)
        {
            String key = (String)i.next();

            assertNotNull("key returned from keySet() iterator was null", key);
            if(key.equals("one"))
                if(sawOne)
                    fail("Key one seen more than once.");
                else
                {
                    sawOne = true;
                    assertEquals("Key one's value was not two", "two", toLoad.getProperty("one"));
                }
            else if(key.equals("two"))
                if(sawTwo)
                    fail("Key two seen more than once.");
                else
                {
                    sawTwo = true;
                    assertEquals("Key two's value was not three", "three", toLoad.getProperty("two"));
                }
             else if(key.equals("seuss.schneier"))
                    if(sawSeuss)
                        fail("Key seuss.schneier seen more than once.");
                    else
                    {
                        sawSeuss = true;
                        assertEquals("Key seuss.schneier's value was not expected value",
                                     "one fish, twofish, red fish, blowfish",
                                     toStore.getProperty("seuss.schneier"));
                    }
            else
                fail("Unset key " + key + " returned from keySet().iterator()");
        }
        assertTrue("Key one was never seen", sawOne);
        assertTrue("Key two was never seen", sawTwo);
    }

    /**
     * Test storing and loading of encrypted properties.
     */
    @Test public void testStoreLoadWithReader() throws Exception
    {
/*
        //create an EncryptedProperties to store
        ReferenceEncryptedProperties toStore = new ReferenceEncryptedProperties();
        toStore.setProperty("one", "two");
        toStore.setProperty("two", "three");
        toStore.setProperty("seuss.schneier", "one fish, twofish, red fish, blowfish");

        //store properties to a Writer
        CharArrayWriter writer = new CharArrayWriter();
        //toStore.store(writer, "testStore");

        //read it back in from a Reader
        Reader reader = new CharArrayReader(writer.toCharArray());

        ReferenceEncryptedProperties toLoad = new ReferenceEncryptedProperties();
        toLoad.load(reader);

        //test the resulting loaded properties
        boolean sawOne = false;
        boolean sawTwo = false;
        boolean sawSeuss = false;

        for(Iterator i=toLoad.keySet().iterator();i.hasNext();)
        {
            String key = (String)i.next();

            assertNotNull("key returned from keySet() iterator was null", key);
            if(key.equals("one"))
                if(sawOne)
                    fail("Key one seen more than once.");
                else
                {
                    sawOne = true;
                    assertEquals("Key one's value was not two", "two", toLoad.getProperty("one"));
                }
            else if(key.equals("two"))
                if(sawTwo)
                    fail("Key two seen more than once.");
                else
                {
                    sawTwo = true;
                    assertEquals("Key two's value was not three", "three", toLoad.getProperty("two"));
                }
             else if(key.equals("seuss.schneier"))
                    if(sawSeuss)
                        fail("Key seuss.schneier seen more than once.");
                    else
                    {
                        sawSeuss = true;
                        assertEquals("Key seuss.schneier's value was not expected value",
                                     "one fish, twofish, red fish, blowfish",
                                     toStore.getProperty("seuss.schneier"));
                    }
            else
                fail("Unset key " + key + " returned from keySet().iterator()");
        }
        assertTrue("Key one was never seen", sawOne);
        assertTrue("Key two was never seen", sawTwo);
*/
    }

    /**
     * Test overridden put method.
     */
    @Test public void testPut() throws Exception
    {
        ReferenceEncryptedProperties props = new ReferenceEncryptedProperties();

        String name = "name";
        String value = "value";

        props.put(name, value);  //should work and store encrypted
        String result = props.getProperty(name);
        assertEquals(value, result);

        Integer five = new Integer(5);

        try {
            props.put("Integer", five); //should fail and throw IllegalArgumentException
            fail("testPut(): Non-String property value did not result in expected exception.");
        } catch( Exception e ) {
            assertTrue( e instanceof IllegalArgumentException );
        }
        try {
            props.put(five, "Integer"); //should fail and throw IllegalArgumentException
            fail("testPut(): Non-String property key did not result in expected exception.");
        } catch( Exception e ) {
            assertTrue( e instanceof IllegalArgumentException );
        }
        try {
            props.put(five, five); //should fail and throw IllegalArgumentException
            fail("testPut(): Non-String property key and value did not result in expected exception.");
        } catch( Exception e ) {
            assertTrue( e instanceof IllegalArgumentException );
        }
        try {
            props.put(null, five);
            fail("testSetProperty(): Null property name and non-String value did not result in expected exception.");
        } catch( Exception e ) {
            assertTrue( e instanceof IllegalArgumentException );
        }
        try {
            props.put(five, null);
            fail("testSetProperty(): Non-String key and null property value did not result in expected exception.");
        } catch( Exception e ) {
            assertTrue( e instanceof IllegalArgumentException );
        }
        try {
            props.put(null, value);
            fail("testSetProperty(): Null property name did not result in expected exception.");
        } catch( Exception e ) {
            assertTrue( e instanceof IllegalArgumentException );
        }
        try {
            props.put(name, null);
            fail("testSetProperty(): Null property value did not result in expected exception.");
        } catch( Exception e ) {
            assertTrue( e instanceof IllegalArgumentException );
        }
        try {
            props.put(null, null);
            fail("testSetProperty(): Null property name and valud did not result in expected exception.");
        } catch( Exception e ) {
            assertTrue( e instanceof IllegalArgumentException );
        }
    }

    /**
     * Test that ReferenceEncryptedProperties can be properly constructed
     * with an instance of Properties.
     */
    @Test public void testConstructWithProperties() {
        Properties props = new Properties();
        props.setProperty("one", "two");
        props.setProperty("two", "three");
        props.setProperty("seuss.schneier", "one fish, twofish, red fish, blowfish");

        ReferenceEncryptedProperties eProps = new ReferenceEncryptedProperties(props);

        boolean sawOne = false;
        boolean sawTwo = false;
        boolean sawSeuss = false;

        for(Iterator i=eProps.keySet().iterator();i.hasNext();)
        {
            String key = (String)i.next();

            assertNotNull("key returned from keySet() iterator was null", key);
            if(key.equals("one"))
                if(sawOne)
                    fail("Key one seen more than once.");
                else
                {
                    sawOne = true;
                    assertEquals("Key one's value was not two", "two", eProps.getProperty("one"));
                }
            else if(key.equals("two"))
                if(sawTwo)
                    fail("Key two seen more than once.");
                else
                {
                    sawTwo = true;
                    assertEquals("Key two's value was not three", "three", eProps.getProperty("two"));
                }
             else if(key.equals("seuss.schneier"))
                    if(sawSeuss)
                        fail("Key seuss.schneier seen more than once.");
                    else
                    {
                        sawSeuss = true;
                        assertEquals("Key seuss.schneier's value was not expected value",
                                     "one fish, twofish, red fish, blowfish",
                                     eProps.getProperty("seuss.schneier"));
                    }
            else
                fail("Unset key " + key + " returned from keySet().iterator()");
        }
        assertTrue("Key one was never seen", sawOne);
        assertTrue("Key two was never seen", sawTwo);
    }

    /**
     * Test that ReferenceEncryptedProperties can be properly constructed
     * with an instance of EncryptedProperties.
     */
    @Test public void testConstructWithEncryptedProperties() throws Exception {
        ReferenceEncryptedProperties props = new ReferenceEncryptedProperties();
        props.setProperty("one", "two");
        props.setProperty("two", "three");
        props.setProperty("seuss.schneier", "one fish, twofish, red fish, blowfish");

        ReferenceEncryptedProperties eProps = new ReferenceEncryptedProperties(props);

        boolean sawOne = false;
        boolean sawTwo = false;
        boolean sawSeuss = false;

        for(Iterator i=eProps.keySet().iterator();i.hasNext();)
        {
            String key = (String)i.next();

            assertNotNull("key returned from keySet() iterator was null", key);
            if(key.equals("one"))
                if(sawOne)
                    fail("Key one seen more than once.");
                else
                {
                    sawOne = true;
                    assertEquals("Key one's value was not two", "two", eProps.getProperty("one"));
                }
            else if(key.equals("two"))
                if(sawTwo)
                    fail("Key two seen more than once.");
                else
                {
                    sawTwo = true;
                    assertEquals("Key two's value was not three", "three", eProps.getProperty("two"));
                }
             else if(key.equals("seuss.schneier"))
                    if(sawSeuss)
                        fail("Key seuss.schneier seen more than once.");
                    else
                    {
                        sawSeuss = true;
                        assertEquals("Key seuss.schneier's value was not expected value",
                                     "one fish, twofish, red fish, blowfish",
                                     eProps.getProperty("seuss.schneier"));
                    }
            else
                fail("Unset key " + key + " returned from keySet().iterator()");
        }
        assertTrue("Key one was never seen", sawOne);
        assertTrue("Key two was never seen", sawTwo);
    }


    /**
     * Test overridden methods from Properties and Hashtable.
     */
    @Test public void testOverriddenMethods() throws Exception {
        Properties props = new ReferenceEncryptedProperties();
        props.setProperty("one", "two");
        props.setProperty("two", "three");
        props.setProperty("seuss.schneier", "one fish, twofish, red fish, blowfish");

        FileOutputStream out = new FileOutputStream(tempFolder.newFile("ReferenceEncryptedProperties.test.txt"));
        PrintStream ps = new PrintStream(out);
        try {
            props.list(ps);
            fail("testOverriddenMethods(): list(PrintStream) did not result in expected Exception");
        } catch( Exception e ) {
            assertTrue( e instanceof UnsupportedOperationException );
        }

        PrintWriter pw = new PrintWriter(new FileWriter(tempFolder.newFile("test.out")));
        try {
            props.list(pw);
            fail("testOverriddenMethods(): list(PrintWriter) did not result in expected Exception");
        } catch( Exception e ) {
            assertTrue( e instanceof UnsupportedOperationException );
        }

        try {
            props.list(ps);
            fail("testOverriddenMethods(): list(PrintStream) did not result in expected Exception");
        } catch( Exception e ) {
            assertTrue( e instanceof UnsupportedOperationException );
        }

        try {
            Collection c = props.values();
            fail("testOverriddenMethods(): values() did not result in expected Exception");
        } catch( Exception e ) {
            assertTrue( e instanceof UnsupportedOperationException );
        }

        try {
            Collection c = props.entrySet();
            fail("testOverriddenMethods(): entrySet() did not result in expected Exception");
        } catch( Exception e ) {
            assertTrue( e instanceof UnsupportedOperationException );
        }

        try {
            Enumeration e = props.elements();
            fail("testOverriddenMethods(): elements() did not result in expected Exception");
        } catch( Exception e ) {
            assertTrue( e instanceof UnsupportedOperationException );
        }
    }

}
