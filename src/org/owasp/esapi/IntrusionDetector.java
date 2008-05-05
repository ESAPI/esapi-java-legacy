/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * http://www.owasp.org/esapi.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the LGPL. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2007
 */
package org.owasp.esapi;

import java.util.Iterator;

import org.owasp.esapi.errors.EnterpriseSecurityException;
import org.owasp.esapi.errors.IntrusionException;

/**
 * Reference implementation of the IIntrusionDetector interface. This
 * implementation monitors EnterpriseSecurityExceptions to see if any user
 * exceeds a configurable threshold in a configurable time period. For example,
 * it can monitor to see if a user exceeds 10 input validation issues in a 1
 * minute period. Or if there are more than 3 authentication problems in a 10
 * second period. More complex implementations are certainly possible, such as
 * one that establishes a baseline of expected behavior, and then detects
 * deviations from that baseline.
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 * @see org.owasp.esapi.interfaces.IIntrusionDetector
 */
public class IntrusionDetector implements org.owasp.esapi.interfaces.IIntrusionDetector {

	/** The logger. */
	private static final Logger logger = Logger.getLogger("ESAPI", "IntrusionDetector");

	public IntrusionDetector() {
	}

	// FIXME: ENHANCE consider allowing both per-user and per-application quotas
	// e.g. number of failed logins per hour is a per-application quota
	
	
	/**
	 * This implementation uses an exception store in each User object to track
	 * exceptions.
	 * 
	 * @param e
	 *            the e
	 * 
	 * @throws IntrusionException
	 *             the intrusion exception
	 * 
	 * @see org.owasp.esapi.interfaces.IIntrusionDetector#addException(org.owasp.esapi.errors.EnterpriseSecurityException)
	 */
	public void addException(Exception e) {
        if ( e instanceof EnterpriseSecurityException ) {
            logger.logWarning( Logger.SECURITY, ((EnterpriseSecurityException)e).getLogMessage(), e );
        } else {
            logger.logWarning( Logger.SECURITY, e.getMessage(), e );
        }

        // add the exception to the current user, which may trigger a detector 
		User user = ESAPI.authenticator().getCurrentUser();
        String eventName = e.getClass().getName();

        // FIXME: AAA Rethink this - IntrusionExceptions which shouldn't get added to the IntrusionDetector
        if ( e instanceof IntrusionException) {
            return;
        }
        
        // add the exception to the user's store, handle IntrusionException if thrown
		try {
			user.addSecurityEvent(eventName);
		} catch( IntrusionException ex ) {
            Threshold quota = ESAPI.securityConfiguration().getQuota(eventName);
            Iterator i = quota.actions.iterator();
            while ( i.hasNext() ) {
                String action = (String)i.next();
                String message = "User exceeded quota of " + quota.count + " per "+ quota.interval +" seconds for event " + eventName + ". Taking actions " + quota.actions;
                takeSecurityAction( action, message );
            }
		}
	}

    /**
     * Adds the event to the IntrusionDetector.
     * 
     * @param event the event
     * @throws IntrusionException the intrusion exception
     */
    public void addEvent(String eventName) throws IntrusionException {
        logger.logWarning( Logger.SECURITY, "Security event " + eventName + " received" );

        // add the event to the current user, which may trigger a detector 
        User user = ESAPI.authenticator().getCurrentUser();
        try {
            user.addSecurityEvent("event." + eventName);
        } catch( IntrusionException ex ) {
            Threshold quota = ESAPI.securityConfiguration().getQuota("event." + eventName);
            Iterator i = quota.actions.iterator();
            while ( i.hasNext() ) {
                String action = (String)i.next();
                String message = "User exceeded quota of " + quota.count + " per "+ quota.interval +" seconds for event " + eventName + ". Taking actions " + quota.actions;
                takeSecurityAction( action, message );
            }
        }
    }

    
    /*
     * FIXME: Enhance - future actions might include SNMP traps, email, pager, etc...
     */
    private void takeSecurityAction( String action, String message ) {
        if ( action.equals( "log" ) ) {
            logger.logCritical( Logger.SECURITY, "INTRUSION - " + message );
        }
        if ( action.equals( "disable" ) ) {
            ESAPI.authenticator().getCurrentUser().disable();
        }
        if ( action.equals( "logout" ) ) {
            ESAPI.authenticator().logout();
        }
    }

}
