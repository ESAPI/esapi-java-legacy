package org.owasp.esapi.util;

import static org.junit.Assert.*;
import junit.framework.JUnit4TestAdapter;

import org.junit.Test;
import org.owasp.esapi.codecs.Hex;

/** JUnit test for {@code ByteConversionUtil}. */
public class ByteConversionUtilTest {

    private static final String EOL = System.getProperty("line.separator", "\n");
    private static final boolean VERBOSE = true;
    
    /**
     * Test conversion byte[] <--> short.
     */
    @Test
    public void testShortConversion() {
        System.err.println("========== testShortConversion() ==========");
        short[] testArray = { -1, 0, 1, Short.MIN_VALUE, Short.MAX_VALUE };
        
        for(int i = 0; i < testArray.length; i++ ) {
            byte[] bytes = ByteConversionUtil.fromShort(testArray[i]);
            short n = ByteConversionUtil.toShort(bytes);
            if ( VERBOSE ) {
                System.err.println("i: " + i + ", value: " + testArray[i]);
                System.err.println("byte array: " + Hex.toHex(bytes, true));
                System.err.println("testArray[" + i + "]: " + Integer.toHexString(testArray[i]));
                System.err.println("n: " + Integer.toHexString(n) + EOL + "-----");
            }
            assertEquals(testArray[i], n);
        }
    }
    
    /**
     * Test conversion byte[] <--> int.
     */
    @Test
    public void testIntConversion() {
        System.err.println("========== testIntConversion() ==========");
        int[] testArray = { -1, 0, 1, Integer.MIN_VALUE, Integer.MAX_VALUE };
        
        for(int i = 0; i < testArray.length; i++ ) {
            byte[] bytes = ByteConversionUtil.fromInt(testArray[i]);
            int n = ByteConversionUtil.toInt(bytes);
            if ( VERBOSE ) {
                System.err.println("i: " + i + ", value: " + testArray[i]);
                System.err.println("byte array: " + Hex.toHex(bytes, true));
                System.err.println("testArray[" + i + "]: " + Integer.toHexString(testArray[i]));
                System.err.println("n: " + Integer.toHexString(n) + EOL + "-----");
            }
            assertEquals(testArray[i], n);
        }
    }
    
    /**
     * Test conversion byte[] <--> long.
     */
    @Test
    public void testLongConversion() {
        System.err.println("========== testLongConversion() ==========");
        long[] testArray = { -1, 0, 1, Long.MIN_VALUE, Long.MAX_VALUE };
        
        for(int i = 0; i < testArray.length; i++ ) {
            byte[] bytes = ByteConversionUtil.fromLong(testArray[i]);
            long n = ByteConversionUtil.toLong(bytes);
            if ( VERBOSE ) {
                System.err.println("i: " + i + ", value: " + testArray[i]);
                System.err.println("byte array: " + Hex.toHex(bytes, true));
                System.err.println("testArray[" + i + "]: " + Long.toHexString(testArray[i]));
                System.err.println("n: " + Long.toHexString(n) + EOL + "-----");
            }
            assertEquals(testArray[i], n);
        }
    }
    
    /**
     * Run all the test cases in this suite.
     * This is to allow running from {@code org.owasp.esapi.AllTests} which
     * uses a JUnit 3 test runner.
     */
    public static junit.framework.Test suite() {
        return new JUnit4TestAdapter(ByteConversionUtilTest.class);
    }
}
