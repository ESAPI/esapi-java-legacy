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

/**
 * LogScrubber implementation which performs iterative delegate to an ordered
 * List of LogScrubbers. <br>
 * The results of the delegate list of LogScrubbers is additive, meaning that
 * the the original message is passed to the first delegate and its return value
 * is passed to the second (etc). <br>
 *
 */
public class CompositeLogScrubber implements LogScrubber {
    /** Delegate scrubbers. */
    private final List<LogScrubber> messageCleaners;

    /**
     * Ctr.
     * 
     * @param orderedCleaner
     *            Ordered List of delegate implementations. Cannot be {@code null}
     */
    public CompositeLogScrubber(List<LogScrubber> orderedCleaner) {
        if (orderedCleaner == null) {
            throw new IllegalArgumentException("Delegate LogScrubber List cannot be null");
        }
        this.messageCleaners = new ArrayList<>(orderedCleaner);
    }

    @Override
    public String cleanMessage(String message) {
        String cleaned = message;

        for (LogScrubber scrubadub : messageCleaners) {
            cleaned = scrubadub.cleanMessage(cleaned);
        }

        return cleaned;
    }
}
