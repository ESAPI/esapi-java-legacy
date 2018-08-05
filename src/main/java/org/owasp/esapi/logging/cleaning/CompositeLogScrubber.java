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
