/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2009
 */

package org.owasp.esapi;

import junit.framework.TestCase;
import org.owasp.esapi.codecs.Codec;
import org.owasp.esapi.codecs.HTMLEntityCodec;

public class PreparedStringTest extends TestCase {

    private final static Codec htmlEntityCodec = new HTMLEntityCodec();

    public void testPreparedString() {
        PreparedString ps1 = new PreparedString( "Test ? is ?", htmlEntityCodec );
        ps1.set( 1, "[]<>;\"\'PreparedString" );
        ps1.set( 2, "cool" );
        try {
            PreparedString ps2 = new PreparedString( "Test ? is ?", htmlEntityCodec );
            ps2.set( 2, "cool" );
        } catch( Exception e ) {
            fail(e.getMessage());
        }

        try {
            PreparedString ps3 = new PreparedString( "Test ? is ?", htmlEntityCodec );
            ps3.set( 1, "[]<>;\"\'PreparedString" );
            ps3.set( 2, "cool" );
            ps3.set( 3, "cool" );
            fail("Was able to set parameters past the end of the parameter stack.");
        } catch( Exception e ) {
            // Success
        }

        try {
            PreparedString ps4 = new PreparedString( "???", htmlEntityCodec );
            ps4.set( 1, "1" );
            ps4.set( 2, "2" );
            ps4.set( 3, "3" );
        } catch( Exception e ) {
            fail(e.getMessage());
        }

        try {
            PreparedString ps5 = new PreparedString( "??x", htmlEntityCodec );
            ps5.set( 1, "1" );
            ps5.set( 2, "2" );
        } catch( Exception e ) {
            fail(e.getMessage());
        }
    }
}
