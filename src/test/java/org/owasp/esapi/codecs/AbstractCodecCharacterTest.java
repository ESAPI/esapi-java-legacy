package org.owasp.esapi.codecs;

import java.util.Arrays;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.owasp.esapi.codecs.Codec;
import org.owasp.esapi.codecs.PushbackString;


/**
 * FIXME:  Document intent of class.  General Function, purpose of creation, intended feature, etc.
 *  Why do people care this exists? 
 * @author Jeremiah
 * @since Jan 20, 2018
 *
 */
@RunWith(Parameterized.class)
public abstract class AbstractCodecCharacterTest {
    
    protected static class CodecCharacterTestTuple {
        Codec codec;
        char[] encodeImmune;
        String input;
        Character decodedValue;
        String description;
        /** {@inheritDoc}*/
        
        @Override
        public String toString() {
            return description != null ? description : codec.getClass().getSimpleName() + "  "+input;
        }
    }

    
    protected final Codec codec;
    protected final String input;
    protected final char[] encodeImmune;
    protected final Character decodedValue;
    
    public AbstractCodecCharacterTest(CodecCharacterTestTuple tuple) {
        this.codec = tuple.codec;
        this.input = tuple.input;
        this.decodedValue = tuple.decodedValue;
        this.encodeImmune = tuple.encodeImmune;
    }
        
    @Test
    public void testEncodeCharacter() {
        Assert.assertEquals(input, codec.encodeCharacter(encodeImmune, decodedValue));
    }
    
    @Test
    public void testEncode() {
        String expected = Arrays.asList(encodeImmune).contains(decodedValue) ? decodedValue.toString() : input;
        Assert.assertEquals(expected, codec.encode(encodeImmune, decodedValue.toString()));
    }
    
    @Test
    public void testDecode() {
         Assert.assertEquals(decodedValue.toString(), codec.decode(input));
    }
    
    
    @Test
    public void testDecodePushbackSequence() {
        Assert.assertEquals(decodedValue, codec.decodeCharacter(new PushbackString(input)));
    }
    
}
