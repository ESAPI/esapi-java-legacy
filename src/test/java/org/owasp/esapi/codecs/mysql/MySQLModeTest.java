package org.owasp.esapi.codecs.mysql;

import java.util.HashMap;
import java.util.Map;

import org.hamcrest.Matcher;
import org.hamcrest.core.IsEqual;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ErrorCollector;
import org.junit.rules.ExpectedException;
import org.mockito.Mockito;
import org.owasp.esapi.codecs.MySQLCodec.Mode;
import org.owasp.esapi.codecs.PushbackSequence;
import org.powermock.reflect.Whitebox;
/**
 * Tests to show {@link MySQLCodec} with {@link Mode#ANSI}
 * comply with the OWASP Escaping recommendations
 * 
 * https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet#MySQL_Escaping
 *
 */
public class MySQLModeTest {
    @Rule
    public ExpectedException exEx = ExpectedException.none();
    
    
    @Test
    public void testCreateAnsiByInt() {
        MySQLCodec codec = new MySQLCodec(MySQLMode.ANSI);
        MySQLMode mode = MySQLMode.findByKey(MySQLMode.ANSI.ordinal());
        MySQLModeSupport support = mode.getModeSupport(codec);
        Assert.assertTrue(support instanceof MySQLAnsiSupport);
    }
    
    @Test
    public void testCreateStandardByInt() {
        MySQLCodec codec = new MySQLCodec(MySQLMode.STANDARD);
        MySQLMode mode = MySQLMode.findByKey(MySQLMode.STANDARD.ordinal());
        MySQLModeSupport support = mode.getModeSupport(codec);
        Assert.assertTrue(support instanceof MySQLStandardSupport);
    }
    
    @Test
    public void testCreateUnsupportedModeByIntTooHigh() {
        exEx.expect(IllegalArgumentException.class);
        String message = String.format("No Mode for %s. Valid references are MySQLStandard: %s or ANSI: %s", MySQLMode.values().length, MySQLCodec.MYSQL_MODE, MySQLCodec.ANSI_MODE);
        exEx.expectMessage(message);
        MySQLMode.findByKey(MySQLMode.values().length);
       
    }
    
    @Test
    public void testCreateUnsupportedModeByIntLessThanZero() {
        exEx.expect(IllegalArgumentException.class);
        String message = String.format("No Mode for %s. Valid references are MySQLStandard: %s or ANSI: %s", -1, MySQLCodec.MYSQL_MODE, MySQLCodec.ANSI_MODE);
        exEx.expectMessage(message);
        MySQLMode.findByKey(-1);
       
    }
}