package org.owasp.esapi.util;

import static org.junit.Assert.*;
import junit.framework.JUnit4TestAdapter;

import org.junit.Test;
import org.owasp.esapi.codecs.Hex;

/** JUnit test for {@code ByteConversionUtil}. */
public class ByteConversionUtilTest {

    private static final String EOL = System.getProperty("line.separator", "\n");
    private static final boolean VERBOSE = false;

    /**
     * Test conversion byte[] <--> short.
     */
    @Test
    public void testShortConversion() {
        debug("========== testShortConversion() ==========");
        short[] testArray = { -1, 0, 1, Short.MIN_VALUE, Short.MAX_VALUE };

        for(int i = 0; i < testArray.length; i++ ) {
            byte[] bytes = ByteConversionUtil.fromShort(testArray[i]);
            short n = ByteConversionUtil.toShort(bytes);
            debug("i: " + i + ", value: " + testArray[i]);
            debug("byte array: " + Hex.toHex(bytes, true));
            debug("testArray[" + i + "]: " + Integer.toHexString(testArray[i]));
            debug("n: " + Integer.toHexString(n) + EOL + "-----");
            assertEquals(testArray[i], n);
        }
    }

    /**
     * Test conversion byte[] <--> int.
     */
    @Test
    public void testIntConversion() {
        debug("========== testIntConversion() ==========");
        int[] testArray = { -1, 0, 1, Integer.MIN_VALUE, Integer.MAX_VALUE };

        for(int i = 0; i < testArray.length; i++ ) {
            byte[] bytes = ByteConversionUtil.fromInt(testArray[i]);
            int n = ByteConversionUtil.toInt(bytes);
            debug("i: " + i + ", value: " + testArray[i]);
            debug("byte array: " + Hex.toHex(bytes, true));
            debug("testArray[" + i + "]: " + Integer.toHexString(testArray[i]));
            debug("n: " + Integer.toHexString(n) + EOL + "-----");
            assertEquals(testArray[i], n);
        }
    }

    /**
     * Test conversion byte[] <--> long.
     */
    @Test
    public void testLongConversion() {
        debug("========== testLongConversion() ==========");
        long[] testArray = { -1, 0, 1, Long.MIN_VALUE, Long.MAX_VALUE };

        for(int i = 0; i < testArray.length; i++ ) {
            byte[] bytes = ByteConversionUtil.fromLong(testArray[i]);
            long n = ByteConversionUtil.toLong(bytes);
            debug("i: " + i + ", value: " + testArray[i]);
            debug("byte array: " + Hex.toHex(bytes, true));
            debug("testArray[" + i + "]: " + Long.toHexString(testArray[i]));
            debug("n: " + Long.toHexString(n) + EOL + "-----");
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

    private void debug(String msg) {
        if ( VERBOSE ) {
            System.err.println(msg);
        }
    }
}
