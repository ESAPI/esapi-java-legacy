package org.owasp.esapi.logging.cleaning;

public class NewlineLogScrubber  implements LogScrubber {
    /* NewLine and Carriage Return Replacement values.*/
    private static final char NEWLINE = '\n';
    private static final char CARRIAGE_RETURN = '\r';
    private static final char LINE_WRAP_REPLACE = '_';
    
    @Override
    public String cleanMessage(String message) {
        return message.replace(NEWLINE, LINE_WRAP_REPLACE).replace(CARRIAGE_RETURN, LINE_WRAP_REPLACE);
    } 
}
