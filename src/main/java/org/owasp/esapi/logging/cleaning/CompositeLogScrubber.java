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

import java.util.ArrayList;
import java.util.List;

public class CompositeLogScrubber  implements LogScrubber {

    private final List<LogScrubber> messageCleaners;
    
    public CompositeLogScrubber(List<LogScrubber> orderedCleaner) {
        this.messageCleaners = new ArrayList<>(orderedCleaner);
    }
    
    @Override
    public String cleanMessage(String message) {
        String cleaned = message;
        
        for(LogScrubber scrubadub : messageCleaners) {
            cleaned = scrubadub.cleanMessage(cleaned);
        }
        
        return cleaned;
    }
}
