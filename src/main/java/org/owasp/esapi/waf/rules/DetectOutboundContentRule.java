/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2009 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author Arshan Dabirsiaghi <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2009
 */
package org.owasp.esapi.waf.rules;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.owasp.esapi.waf.actions.Action;
import org.owasp.esapi.waf.actions.DefaultAction;
import org.owasp.esapi.waf.actions.DoNothingAction;
import org.owasp.esapi.waf.configuration.AppGuardianConfiguration;
import org.owasp.esapi.waf.internal.InterceptingHTTPServletResponse;

/**
 * This is the Rule subclass executed for &lt;detect-content&gt; rules.
 * @author Arshan Dabirsiaghi
 *
 */
public class DetectOutboundContentRule extends Rule {

    private Pattern contentType;
    private Pattern pattern;
    private Pattern uri;

    public DetectOutboundContentRule(String id, Pattern contentType, Pattern pattern, Pattern uri) {
        this.contentType = contentType;
        this.pattern = pattern;
        this.uri = uri;
        setId(id);
    }

    public Action check(HttpServletRequest request,
            InterceptingHTTPServletResponse response,
            HttpServletResponse httpResponse) {

        /*
         * Early fail: if URI doesn't match.
         */
        if ( uri != null && ! uri.matcher(request.getRequestURI()).matches() ) {
            return new DoNothingAction();
        }

        /*
         * Early fail: if the content type is one we'd like to search for output patterns.
         */

        String inboundContentType;
        String charEnc;

        if ( response != null ) {
            if ( response.getContentType() == null ) {
                response.setContentType(AppGuardianConfiguration.DEFAULT_CONTENT_TYPE);
            }
            inboundContentType = response.getContentType();
            charEnc = response.getCharacterEncoding();

        } else {
            if ( httpResponse.getContentType() == null ) {
                httpResponse.setContentType(AppGuardianConfiguration.DEFAULT_CONTENT_TYPE);
            }
            inboundContentType = httpResponse.getContentType();
            charEnc = httpResponse.getCharacterEncoding();
        }

        if ( contentType.matcher(inboundContentType).matches() ) {
            /*
             * Depending on the encoding, search through the bytes
             * for the pattern.
             */
            try {

                byte[] bytes = null;

                try {
                    bytes = response.getInterceptingServletOutputStream().getResponseBytes();
                } catch (IOException ioe) {
                    log(request,"Error matching pattern '" + pattern.pattern() + "', IOException encountered (possibly too large?): " + ioe.getMessage() + " (in response to URL: '" + request.getRequestURL() + "')");
                    return new DoNothingAction(); // yes this is a fail open!
                }

                String s = new String(bytes,charEnc);

                if ( pattern.matcher(s).matches() ) {

                    log(request,"Content pattern '" + pattern.pattern() + "' was found in response to URL: '" + request.getRequestURL() + "'");
                    return new DefaultAction();

                }

            } catch (UnsupportedEncodingException uee) {
                log(request,"Content pattern '" + pattern.pattern() + "' could not be found due to encoding error: " + uee.getMessage());
            }
        }

        return new DoNothingAction();

    }

}
