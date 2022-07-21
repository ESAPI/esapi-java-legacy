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
 * @created 2007
 */
package org.owasp.esapi.reference;

import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Stack;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Logger;
import org.owasp.esapi.User;
import org.owasp.esapi.SecurityConfiguration.Threshold;
import org.owasp.esapi.errors.EnterpriseSecurityException;
import org.owasp.esapi.errors.IntrusionException;

/**
 * Reference implementation of the IntrusionDetector interface. This
 * implementation monitors EnterpriseSecurityExceptions to see if any user
 * exceeds a configurable threshold in a configurable time period. For example,
 * it can monitor to see if a user exceeds 10 input validation issues in a 1
 * minute period. Or if there are more than 3 authentication problems in a 10
 * second period. More complex implementations are certainly possible, such as
 * one that establishes a baseline of expected behavior, and then detects
 * deviations from that baseline. This implementation stores state in the
 * user's session, so that it will be properly cleaned up when the session is
 * terminated. State is not otherwise persisted, so attacks that span sessions
 * will not be detectable.
 *
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 * @see org.owasp.esapi.IntrusionDetector
 */
public class DefaultIntrusionDetector implements org.owasp.esapi.IntrusionDetector {

    /** The logger. */
    private final Logger logger = ESAPI.getLogger("IntrusionDetector");

    public DefaultIntrusionDetector() {
    }

    /**
     * {@inheritDoc}
     *
     * @param e
     */
    public void addException(Exception e) {
        if (ESAPI.securityConfiguration().getDisableIntrusionDetection()) return;

        if ( e instanceof EnterpriseSecurityException ) {
            logger.warning( Logger.SECURITY_FAILURE, ((EnterpriseSecurityException)e).getLogMessage(), e );
        } else {
            logger.warning( Logger.SECURITY_FAILURE, e.getMessage(), e );
        }

        // add the exception to the current user, which may trigger a detector
        User user = ESAPI.authenticator().getCurrentUser();
        String eventName = e.getClass().getName();

        if ( e instanceof IntrusionException) {
            return;
        }

        // add the exception to the user's store, handle IntrusionException if thrown
        try {
            addSecurityEvent(user, eventName);
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
     * {@inheritDoc}
     */
    public void addEvent(String eventName, String logMessage) throws IntrusionException {
        if (ESAPI.securityConfiguration().getDisableIntrusionDetection()) return;

        logger.warning( Logger.SECURITY_FAILURE, "Security event " + eventName + " received : " + logMessage );

        // add the event to the current user, which may trigger a detector
        User user = ESAPI.authenticator().getCurrentUser();
        try {
            addSecurityEvent(user, "event." + eventName);
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

    /**
     * Take a specified security action.  In this implementation, acceptable
     * actions are: log, disable, logout.
     *
     * @param action
     *         the action to take (log, disable, logout)
     * @param message
     *         the message to log if the action is "log"
     */
    private void takeSecurityAction( String action, String message ) {
        if (ESAPI.securityConfiguration().getDisableIntrusionDetection()) return;

        if ( action.equals( "log" ) ) {
            logger.fatal( Logger.SECURITY_FAILURE, "INTRUSION - " + message );
        }
        User user = ESAPI.authenticator().getCurrentUser();
        if (user == User.ANONYMOUS)
            return;
        if ( action.equals( "disable" ) ) {
            user.disable();
        }
        if ( action.equals( "logout" ) ) {
            user.logout();
        }
    }

     /**
     * Adds a security event to the user.  These events are used to check that the user has not
     * reached the security thresholds set in the properties file.
     *
     * @param user
     *             The user that caused the event.
     * @param eventName
     *             The name of the event that occurred.
     */
    private void addSecurityEvent(User user, String eventName) {
        if (ESAPI.securityConfiguration().getDisableIntrusionDetection()) return;

        if ( user.isAnonymous() ) return;

        HashMap eventMap = user.getEventMap();

        // if there is a threshold, then track this event
        Threshold threshold = ESAPI.securityConfiguration().getQuota( eventName );
        if ( threshold != null ) {
            Event event = (Event)eventMap.get( eventName );
            if ( event == null ) {
                event = new Event( eventName );
                eventMap.put( eventName, event );
            }
            // increment
            event.increment(threshold.count, threshold.interval);
        }
    }

    private static class Event {
        public String key;
        public Stack times = new Stack();
        //public long count = 0;
        public Event( String key ) {
            this.key = key;
        }
        public void increment(int count, long interval) throws IntrusionException {
            if (ESAPI.securityConfiguration().getDisableIntrusionDetection()) return;

            Date now = new Date();
            times.add( 0, now );
            while ( times.size() > count ) times.remove( times.size()-1 );
            if ( times.size() == count ) {
                Date past = (Date)times.get( count-1 );
                long plong = past.getTime();
                long nlong = now.getTime();
                if ( nlong - plong < interval * 1000 ) {
                    throw new IntrusionException( "Threshold exceeded", "Exceeded threshold for " + key );
                }
            }
        }
    }
}
