package org.owasp.esapi.codecs.mysql;


public enum MySQLMode {
    STANDARD {
        @Override
        MySQLModeSupport getModeSupport(MySQLCodec reference) {
            return new MySQLStandardSupport(reference);
        }
    },
    ANSI {
        @Override
        MySQLModeSupport getModeSupport(MySQLCodec reference) {
            return new MySQLAnsiSupport();
        }
    };


    static MySQLMode findByKey(int key) {
        if (key < 0 || key > (MySQLMode.values().length - 1) ) {
            String message = String.format("No Mode for %s. Valid references are MySQLStandard: %s or ANSI: %s ", key, STANDARD.ordinal(), ANSI.ordinal());  
            throw new IllegalArgumentException(message);
        }

        //Use Key as ordinal reference.
        return MySQLMode.values()[key]; 
    }

    /*package */ abstract MySQLModeSupport getModeSupport(MySQLCodec reference);
}
