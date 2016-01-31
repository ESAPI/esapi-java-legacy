package org.owasp.esapi.codecs;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.owasp.esapi.EncoderConstants;
import org.owasp.esapi.StringUtilities;
import org.owasp.esapi.codecs.*;

/**
 * Parameterized test to verify that the Immunity parameter for a codec
 * encode/decode event works as expected on a series of special characters.
 *  
 * @author jeremiah.j.stacey@gmail.com
 * @since 2.1.0.1
 *
 */
@RunWith(Parameterized.class)
public class CodecImmunityTest {
    /** character arrays used as immunity lists from Default Encoder.*/
    private final static char[] IMMUNE_HTML = { ',', '.', '-', '_', ' ' };
    private final static char[] IMMUNE_HTMLATTR = { ',', '.', '-', '_' };
    private final static char[] IMMUNE_CSS = {};
    private final static char[] IMMUNE_JAVASCRIPT = { ',', '.', '_' };
    private final static char[] IMMUNE_VBSCRIPT = { ',', '.', '_' };
    private final static char[] IMMUNE_XML = { ',', '.', '-', '_', ' ' };
    private final static char[] IMMUNE_SQL = { ' ' };
    private final static char[] IMMUNE_OS = { '-' };
    private final static char[] IMMUNE_XMLATTR = { ',', '.', '-', '_' };
    private final static char[] IMMUNE_XPATH = { ',', '.', '-', '_', ' ' };
    private final static char[] IMMUNE_PERCENT = { '%' };
    // These are inline in the encode methods, but same principle.
    // private final static char[] IMMUNE_LDAP = { '\\', '*', '(', ')', '\0' };
    // private final static char[] IMMUNE_DN = { '\\', ',', '+', '"', '<', '>', ';' };


    @Parameters(name = "{0}")
    public static Collection<Object[]> getParams() {
        Collection<Codec> knownCodecs = new ArrayList<Codec>();
        knownCodecs.add(new CSSCodec());
        knownCodecs.add(new DB2Codec());
        knownCodecs.add(new HTMLEntityCodec());
        knownCodecs.add(new JavaScriptCodec());
        knownCodecs.add(new MySQLCodec(0)); //Standard
        knownCodecs.add(new MySQLCodec(1)); //ANSI
        knownCodecs.add(new OracleCodec());
        knownCodecs.add(new PercentCodec());
        knownCodecs.add(new UnixCodec());
        knownCodecs.add(new VBScriptCodec());
        knownCodecs.add(new WindowsCodec());
        knownCodecs.add(new XMLEntityCodec());

        // TODO:  Add more strings here!!
        List<String> sampleStrings = Arrays.asList("%De");

        Collection<Object[]> params = new ArrayList<Object[]>();
        for (Codec codec : knownCodecs) {
            for (String sample : sampleStrings) {
                params.add(new Object[]{codec.getClass().getSimpleName() + " " + sample, codec, sample});
            }
        }

        // Add Tests for codecs against the configured ImmunityLists within the Default Encoder.
        params.addAll(buildImmunitiyValidation(new HTMLEntityCodec(), IMMUNE_HTML, "IMMUNE_HTML"));
        params.addAll(buildImmunitiyValidation(new HTMLEntityCodec(), IMMUNE_XPATH, "IMMUNE_XPATH"));
        params.addAll(buildImmunitiyValidation(new HTMLEntityCodec(), IMMUNE_HTMLATTR, "IMMUNE_HTMLATTR"));
        params.addAll(buildImmunitiyValidation(new CSSCodec(), IMMUNE_CSS, "IMMUNE_CSS"));
        //params.addAll(buildImmunitiyValidation(new DB2Codec(), IMMUNE_HTML, ""));
        params.addAll(buildImmunitiyValidation(new JavaScriptCodec(), IMMUNE_JAVASCRIPT, "IMMUNE_JAVASCRIPT"));
        params.addAll(buildImmunitiyValidation(new MySQLCodec(0), IMMUNE_SQL, "IMMUNE_SQL"));
        params.addAll(buildImmunitiyValidation(new MySQLCodec(1), IMMUNE_SQL, "IMMUNE_SQL"));
        params.addAll(buildImmunitiyValidation(new OracleCodec(), IMMUNE_HTML, "IMMUNE_HTML"));
            // No standard Immunity char array defined for PercentEncoder, but for
            // GitHub issues #306 and $350, we use '%'.
        params.addAll(buildImmunitiyValidation(new PercentCodec(), IMMUNE_PERCENT, "IMMUNE_PERCENT"));
        params.addAll(buildImmunitiyValidation(new UnixCodec(), IMMUNE_OS, "IMMUNE_OS"));
        params.addAll(buildImmunitiyValidation(new VBScriptCodec(), IMMUNE_VBSCRIPT, "IMMUNE_VBSCRIPT"));
        params.addAll(buildImmunitiyValidation(new WindowsCodec(), IMMUNE_OS, "IMMUNE_OS"));
        params.addAll(buildImmunitiyValidation(new XMLEntityCodec(), IMMUNE_XML, "IMMUNE_XML"));
        params.addAll(buildImmunitiyValidation(new XMLEntityCodec(), IMMUNE_XMLATTR, "IMMUNE_XMLATTR"));

        params.addAll(fullCharacterCodecValidation(knownCodecs));

        return params;
    }

    private static Collection<Object[]> buildImmunitiyValidation(Codec codec, char[] immunities, String descriptor) {
        Collection<Object[]> params = new ArrayList<Object[]>();
        for (char c : immunities) {
            params.add(new Object[]{codec.getClass().getSimpleName() + " " + descriptor + " ("+ c + ")", codec, String.valueOf(c)});
        }
        return params;
    }

    private static Collection<Object[]> fullCharacterCodecValidation(Collection<Codec> codecs) {
        char[] holyCowTesting = StringUtilities.union(EncoderConstants.CHAR_ALPHANUMERICS, EncoderConstants.CHAR_SPECIALS); 
        Collection<Object[]> params = new ArrayList<Object[]>();
        for (Codec codec: codecs) {
            params.addAll(buildImmunitiyValidation(codec, holyCowTesting, "Full_ALPHA_AND_SPECIALS"));
        }

        return params;
    }

    private final Codec codec;
    private final String string;
    private final char[] immunityList;

    public CodecImmunityTest(String ignored, Codec codec, String toTest) {
        this.codec = codec;
        this.string = toTest;
        /**
         * The Immunity character array is every character in the String we're testing.
         * 
         */
        this.immunityList = toTest.toCharArray();
    }

    @Test
    public void testImmuneEncode() {
        String encoded = codec.encode(immunityList, string);
        Assert.assertEquals(string, encoded);
    }
    /*
    @Test
    public void testImmuneDecode() {
        String decoded = codec.decode(string);
        Assert.assertEquals(string, decoded);
    }
*/
}
