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
package org.owasp.esapi.filters;

import java.io.IOException;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.owasp.esapi.ESAPI;

/**
 * This filter wraps the incoming request and outgoing response and overrides
 * many methods with safer versions. Many of the safer versions simply validate
 * parts of the request or response for unwanted characters before allowing the
 * call to complete. Some examples of attacks that use these
 * vectors include request splitting, response splitting, and file download
 * injection. Attackers use techniques like CRLF injection and null byte injection
 * to confuse the parsing of requests and responses.
 */


public class SafeHTTPFilter implements Filter {

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
    
        if (!(request instanceof HttpServletRequest)) {
            chain.doFilter(request, response);
            return;
        }
        HttpServletRequest hrequest = (HttpServletRequest)request;
        HttpServletResponse hresponse = (HttpServletResponse)response;
        ESAPI.httpUtilities().setCurrentHTTP(hrequest, hresponse);
        
        boolean isExcluded = isExcludedURL(hrequest);
        
        if (isExcluded) {
            chain.doFilter(hrequest, hresponse);
        } else {
            chain.doFilter(new SafeRequest(hrequest), new SafeResponse(hresponse));
        }
    }

    /**
     * Ensure that the target URL is not purposefully being ignored by the SafeHTTPFilter.
     * 
     * @param hrequest
     * @return
     */
    private boolean isExcludedURL(HttpServletRequest hrequest) {
        String targetURL = hrequest.getRequestURL().toString(); 
        
        //first: look for an exact URL match
        List exactIgnoreURLS = ESAPI.securityConfiguration().getSafeHTTPFilterIgnoreURLexact();
        if (exactIgnoreURLS.contains(targetURL)) return true;
        
        //second: look for a "root" match but only if the root is not empty
        List rootIgnoreURLS = ESAPI.securityConfiguration().getSafeHTTPFilterIgnoreURLroot();
        Iterator i = rootIgnoreURLS.iterator();
        while (i.hasNext()) {
            String urlRoot = (String) i.next();
            if (!isEmpty(urlRoot) && targetURL.startsWith(urlRoot.toLowerCase())) {
                return true;
            }
        }

        //third: look for a context root match
        // Construct the full URI, including the query string for comparison  
        String requestURIPlusQueryString;
        String queryString = hrequest.getQueryString();

        if (queryString != null) {
            requestURIPlusQueryString = targetURL + "?" + queryString;
        } else {
            requestURIPlusQueryString = targetURL;
        }

        List contextRootIgnoreURLS = ESAPI.securityConfiguration().getSafeHTTPFilterIgnoreContextURLRoot();
        i = contextRootIgnoreURLS.iterator();

        while (i.hasNext()) {
            String contextUrlRoot = (String) i.next();
            if (!isEmpty(contextUrlRoot) && requestURIPlusQueryString.toLowerCase().startsWith(contextUrlRoot.toLowerCase())) {
                return true;
            }
        }

        //fourth: look for a regular expression match
        List regexIgnoreURLS = ESAPI.securityConfiguration().getSafeHTTPFilterIgnoreURLregEx();
        i = regexIgnoreURLS.iterator();
        while (i.hasNext()) {
            String urlRegex = (String) i.next();
            
            Pattern p = null;
            if ( p == null ) {
                try {
                    p = Pattern.compile(urlRegex);
                } catch( PatternSyntaxException e ) {
                    throw new RuntimeException( "SafeHTTPFilter misconfiguration, invalid regular expression. Bad RegEx=" + urlRegex);
                }
            }
            
            if (p == null) throw new RuntimeException( "SafeHTTPFilter misconfiguration, RegEx compiles to null. Bad RegEx=" + urlRegex);

            if ( p.matcher(targetURL).matches() ) {
                return true;
            }
        }
        
        //last no match, lets make this request SAFE(r)!
        return false;
    }
        
    public void destroy() {
        // no special action
    }
    
    public void init(FilterConfig filterConfig) throws ServletException {
        // no special action
    }
	
    
    private boolean isEmpty(String data) {
        if (data == null) return true;
        if ("".equals(data.trim())) return true;
        return false;
    }
}
