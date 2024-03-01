package org.owasp.esapi.codecs;

import static org.junit.Assert.assertEquals;

import org.junit.Ignore;
import org.junit.Test;

public class HTMLEntityCodecTest {
    Codec<Integer> codec = new HTMLEntityCodec();

    @Test
    public void testEntityDecoding(){
        assertEquals("<", codec.decode("&lt;"));
        assertEquals( "<", codec.decode("&LT"));
        assertEquals( "<", codec.decode("&lt;"));
        assertEquals( "<", codec.decode("&LT;"));
    }

    @Test
    public void test32BitCJK(){
        String s = "𡘾𦴩𥻂";
        String expected = "&#x2163e;&#x26d29;&#x25ec2;";
        String bad = "&#xd845;&#xde3e;&#xd85b;&#xdd29;&#xd857;&#xdec2;";
        assertEquals(false, expected.equals(bad));
        assertEquals(expected, codec.encode(new char[0], s));
    }

    @Test
    public void test32BitCJKMixedWithBmp(){
        String s = "𡘾𦴩<𥻂";
        String expected = "&#x2163e;&#x26d29;&lt;&#x25ec2;";
        String bad = "&#xd845;&#xde3e;&#xd85b;&#xdd29;&#xd857;&#xdec2;";
        assertEquals(false, expected.equals(bad));
        assertEquals(expected, codec.encode(new char[0], s));
    }

    @Test
    public void testDecodeforChars(){
        String s = "!@$%()=+{}[]";
        String expected = "!@$%()=+{}[]";
        assertEquals(expected, codec.decode(s));
    }

    @Test
    public void testMixedBmpAndNonBmp(){
        String nonBMP = new String(new int[]{0x2f804}, 0, 1);
        String bmp = "<a";
        String expected = "&lt;a&#x2f804;";
        String input = bmp + nonBMP;
        assertEquals(expected, codec.encode(new char[0], input));
    }
    
    @Test
    /**
     * TODO:  The following methods are unit tests I'm checking in for an issue to be worked and fixed.  
     */
    @Ignore("Pre check-in for issue #827")
    public void testIssue827() {
    	String input = "/webapp/ux/home?d=1705914006565&status=login&ticket=1705914090394_HzJpTROVfhW-JhRW0OqDbHu7tWXXlgrKSUmOzIMsZNCcUIiYGMXX_Q%3D%3D&newsess=false&roleid=DP010101/0007&origin=ourprogram";
    	String expected = input;  
    	assertEquals(expected, codec.decode(input));
    }
    
    @Test
    @Ignore("Pre check-in for issue #827")
    public void testIssue827OnlyOR() {
    	String input = "&origin=ourprogram";
    	String expected = input;  
    	assertEquals(expected, codec.decode(input));
    }
}
