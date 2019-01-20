package org.owasp.esapi.codecs.mysql;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.owasp.esapi.codecs.PushbackSequence;
import org.owasp.esapi.codecs.MySQLCodec.Mode;
import org.powermock.reflect.Whitebox;
/**
 * Tests to show {@link MySQLCodec} with {@link Mode#ANSI}
 * comply with the OWASP Escaping recommendations
 * 
 * https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet#MySQL_Escaping
 *
 */
public class MySQLCodecTest {
    private static final String MODE_SUPPORT_FIELD = "modeSupport";
    
    @Rule
    public ExpectedException exEx = ExpectedException.none();
    
    private MySQLCodec uit;
    
    private MySQLModeSupport mockSupport;
    
    @Before
    public void setup() {
        uit = new MySQLCodec(MySQLMode.ANSI);
        mockSupport = Mockito.mock(MySQLModeSupport.class);
        
        Whitebox.setInternalState(uit, MODE_SUPPORT_FIELD, mockSupport);
        uit = Mockito.spy(uit);
    }
    
    @Test
    public void testCreateAnsiByInt() {
        MySQLCodec codec = new MySQLCodec(MySQLCodec.ANSI_MODE);
        Object configMode = Whitebox.getInternalState(codec, MODE_SUPPORT_FIELD);
        Assert.assertTrue(configMode instanceof MySQLAnsiSupport);
    }
    
    @Test
    public void testCreateStandardByInt() {
        MySQLCodec codec = new MySQLCodec(MySQLCodec.MYSQL_MODE);
        Object configMode = Whitebox.getInternalState(codec, MODE_SUPPORT_FIELD);
        Assert.assertTrue(configMode instanceof MySQLStandardSupport);
    }
    
    @Test
    public void testCreateAnsiByMode() {
        MySQLCodec codec = new MySQLCodec(MySQLMode.ANSI);
        Object configMode = Whitebox.getInternalState(codec, MODE_SUPPORT_FIELD);
        Assert.assertTrue(configMode instanceof MySQLAnsiSupport);
    }
    
    @Test
    public void testCreateStandardByMode() {
        MySQLCodec codec = new MySQLCodec(MySQLMode.STANDARD);
        Object configMode = Whitebox.getInternalState(codec, MODE_SUPPORT_FIELD);
        Assert.assertTrue(configMode instanceof MySQLStandardSupport);
    }
 
    @Test
    public void testCtrThrowsOnNullMode() {
        exEx.expect(IllegalArgumentException.class);
        exEx.expectMessage("MySQLMode reference cannot be null");
        new MySQLCodec(null);
    }
    
    @Test
    public void testFastReturnOnImmuneCharEncode() {
        char[] immuneset = new char[0];
        Character ch = 'H';
        
        Mockito.doReturn(true).when(uit).containsCharacter(ch.charValue(), immuneset);
        
        String result = uit.encodeCharacter(immuneset, ch);
        Assert.assertEquals(ch.toString(), result);
        
        Mockito.verify(uit, Mockito.times(1)).containsCharacter(ch.charValue(), immuneset);
        Mockito.verify(mockSupport, Mockito.never()).encodeCharacter(ArgumentMatchers.anyChar());
        
    }
    
    @Test
    public void testCharEncodeSupportDelegation() {
        char[] immuneset = new char[0];
        Character ch = 'H';
        String expected = "This is your test-ENCODED value";
        Mockito.when(mockSupport.encodeCharacter(ch)).thenReturn(expected);
        String result = uit.encodeCharacter(immuneset, ch);
        Assert.assertEquals(expected, result);
        
        Mockito.verify(uit, Mockito.times(1)).containsCharacter(ch.charValue(), immuneset);
        Mockito.verify(mockSupport,  Mockito.times(1)).encodeCharacter(ch);
        
    }
    
    @Test
    public void testCharDecodeSupportDelegation() {
        char[] immuneset = new char[0];
        Character ch = 'H';
        PushbackSequence<Character> seq = Mockito.mock(PushbackSequence.class);
        Mockito.when(mockSupport.decodeCharacter(seq)).thenReturn(ch);

        Character result = uit.decodeCharacter(seq);
        Assert.assertEquals(ch, result);
        
        Mockito.verify(mockSupport,  Mockito.times(1)).decodeCharacter(seq);
        
    }
}
