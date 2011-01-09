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
 * @author Chris Schmidt (chris.schmidt@owasp.org)
 * @created 2010
 */
package org.owasp.esapi.crypto;

import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

public class CryptoDiscoverer {
	private static String EOL = System.getProperty("line.separator", "\n");
	
    public static void main(String... args) {
        String provider = ".*";
        String algorithm = ".*";

        if ( args.length > 0 ) {
            if ( args[0].equals( "--help" ) ) {
                usage();
                System.exit(0);
            }

            List<String> argList = Arrays.asList( args );

            int argIdx = argList.indexOf("--provider");
            if ( argIdx > -1 && argList.size() > (argIdx + 1) ) {
                provider = argList.get(argIdx+1);
            }

            argIdx = argList.indexOf("--algorithm");
            if ( argIdx > -1 && argList.size() > (argIdx + 1) ) {
                algorithm = argList.get(argIdx+1);
            }
        }

        Pattern providerPattern = Pattern.compile(provider);
        Pattern algorithmPattern = Pattern.compile(algorithm);

        System.out.println("Searching for Providers Matching: " + provider );
        System.out.println("Searching for Algorithms Matching: " + algorithm );
        System.out.println();

        for (Provider p : Security.getProviders()) {
            if ( providerPattern.matcher(p.getName()).matches()) {
                System.out.println("Provider: " + p.getName());
                for (Provider.Service service : p.getServices()) {
                    if ( algorithmPattern.matcher(service.getAlgorithm()).matches()) {
                        System.out.println("\tAlgorithm: " + service.getAlgorithm());
                    }
                }
            }
        }
    }

    private static void usage() {
        System.out.println("CryptoDiscoverer - Discover or Query for available Crypto Providers and Algorithms");
        System.out.println(EOL + "\t--help\t\t\t\t\tShows this message" + EOL +
        		"\t--provider <regex>\t\tSearch for particular Provider" + EOL +
                "\t--algorithm <regex>\t\tSearch for a particular Algorithm" + EOL + EOL);
    }
}
