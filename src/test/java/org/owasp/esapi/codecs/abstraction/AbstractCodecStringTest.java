/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2008-2018 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 */

package org.owasp.esapi.codecs.abstraction;

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.owasp.esapi.codecs.Codec;


/**
 * Abstract parameterized test case meant to assist with verifying String api of a Codec implementation.
 * <br/>
 * Sub-classes are expected to provide instances of {@link CodecStringTestTuple} to this instance.
 * <br/>
 * For better test naming output specify {@link CodecStringTestTuple#description} and use <code> @Parameters (name="{0}")</code>,
 * where '0' is the index that the CodecStringTestTuple reference appears in the constructor.
 */
@RunWith(Parameterized.class)
public abstract class AbstractCodecStringTest {
   
    protected static class CodecStringTestTuple {
        /** Codec reference to be tested.*/
        public Codec codec;
        /** Set of characters that should be considered 'immune' from decoding processes.*/
        public char[] encodeImmune;
        /** A String representing a contextually encoded String.*/
        public String input;
        /** The decoded representation of the input value.*/
        public String decodedValue;
        /** Optional field to override the toString value of this tuple. */
        public String description;
        
        /**Default public constructor.*/
        public CodecStringTestTuple() { /* No Op*/ }
        
        /** {@inheritDoc}*/
        @Override
        public String toString() {
            return description != null ? description : codec.getClass().getSimpleName() + "  "+input;
        }
    }
    private final Codec codec;
    private final String input;
    private final char[] encodeImmune;
    private final String decodedValue;
    
    public AbstractCodecStringTest(CodecStringTestTuple tuple) {
        this.codec = tuple.codec;
        this.input = tuple.input;
        this.decodedValue = tuple.decodedValue;
        this.encodeImmune = tuple.encodeImmune;
    }
    

    /** Checks that when the input is decoded using the specified codec, that the return matches the expected decoded value.*/
    @Test
    public void testDecode() {
        assertEquals(decodedValue, codec.decode(input));
    }
  
    /** Checks that when the decoded value is encoded (using immunity), that the return matches the provided input.*/
    @Test
    public void testEncode() {
        assertEquals(input, codec.encode(encodeImmune, decodedValue));
    }
    
}
