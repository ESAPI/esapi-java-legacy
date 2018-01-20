package org.owasp.esapi.codecs;

import java.util.Arrays;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.owasp.esapi.codecs.Codec;


/**
 * FIXME:  Document intent of class.  General Function, purpose of creation, intended feature, etc.
 *  Why do people care this exists? 
 * @author Jeremiah
 * @since Jan 20, 2018
 *
 */
@RunWith(Parameterized.class)
public abstract class AbstractCodecStringTest {
   
    protected static class CodecStringTestTuple {
        Codec codec;
        char[] encodeImmune;
        String input;
        String decodedValue;
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
    
    @Test
    public void testDecode() {
        Assert.assertEquals(decodedValue, codec.decode(input));
    }
  
    
    @Test
    public void testEncode() {
        String expected = Arrays.asList(encodeImmune).contains(decodedValue) ? decodedValue : input;
        Assert.assertEquals(expected, codec.encode(encodeImmune, decodedValue));
    }
    
}
