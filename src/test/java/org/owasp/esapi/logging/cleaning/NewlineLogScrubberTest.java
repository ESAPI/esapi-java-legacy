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
 * @created 2018
 */
package org.owasp.esapi.logging.cleaning;

import static org.junit.Assert.assertEquals;
import org.junit.Test;

public class NewlineLogScrubberTest {

    private NewlineLogScrubber scrubber = new NewlineLogScrubber();

    @Test
    public void testReplaceR() {
        String cleanedr = scrubber.cleanMessage("\r");
        assertEquals("_", cleanedr);
    }

    @Test
    public void testReplaceN() {
        String cleanedc = scrubber.cleanMessage("\n");
        assertEquals("_", cleanedc);
    }

    @Test
    public void testNoReplacement() {
        String cleanedc = scrubber.cleanMessage("This content should remain unchanged");
        assertEquals("This content should remain unchanged", cleanedc);
    }

}
