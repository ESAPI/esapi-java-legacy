package org.owasp.esapi.codecs;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;


/**
 * Abstract parameterized test case meant to assist with verifying String api of a Codec implementation.
 * <br/>
 * Sub-classes are expected to provide instances of {@link CodecStringTestTuple} to this instance.
 * <br/>
 * For better test naming output specify {@link CodecStringTestTuple#description} and use {@code} @Parameters (name="{0}")},
 * where '0' is the index that the CodecStringTestTuple reference appears in the constructor.
 */
@RunWith(Parameterized.class)
public abstract class AbstractCodecStringTest {
   
    protected static class CodecStringTestTuple {
        /** Codec reference to be tested.*/
        Codec codec;
        /** Set of characters that should be considered 'immune' from decoding processes.*/
        char[] encodeImmune;
        /** A String representing a contextually encoded String.*/
        String input;
        /** The decoded representation of the input value.*/
        String decodedValue;
        /** Optional field to override the toString value of this tuple. */
        String description;
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
        Assert.assertEquals(decodedValue, codec.decode(input));
    }
  
    /** Checks that when the decoded value is encoded (using immunity), that the return matches the provided input.*/
    @Test
    public void testEncode() {
        Assert.assertEquals(input, codec.encode(encodeImmune, decodedValue));
    }
    
}
