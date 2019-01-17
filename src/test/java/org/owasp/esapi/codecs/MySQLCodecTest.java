package org.owasp.esapi.codecs;

import org.junit.Assert;
import org.junit.Test;
import org.owasp.esapi.codecs.MySQLCodec.Mode;

public class MySQLCodecTest {
    private static final char[] EMPTY_CHAR_ARRAY = new char[0];
    private MySQLCodec uitStandard = new MySQLCodec(Mode.STANDARD);
    private MySQLCodec uitAnsi = new MySQLCodec(Mode.ANSI);

    /*
     * FROM GIT ISSUE 31
     * The "" and" %" characters are escaped but
     * http://mirror.yandex.ru/mirrors/ftp.mysql.com/doc/refman/5.0/en/string-syntax
     * .html specifies that these characters have specific behaviours :"If you use
     * “%” or “_” outside of pattern-matching contexts, they evaluate to the strings
     * “%” and “”, not to “%” and “_”. "
     */
    
    //more referece :  http://doc.nuodb.com/Latest/Content/SQL-Pattern-Matching.htm
    @Test
    public void testEncodeUnderscoreStandard() {
        String encoded = uitStandard.encode(EMPTY_CHAR_ARRAY,"'TEST_1'");

        Assert.assertEquals("\\'TEST\\_1\\'",
                encoded);

    }

    @Test
    public void testEncodeUnderscoreAnsi() {
        String encoded = uitAnsi.encode(EMPTY_CHAR_ARRAY,"'TEST_1'");

        Assert.assertEquals("''TEST_1''",  encoded);
        
    }

}
