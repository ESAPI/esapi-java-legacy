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

import java.util.List;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.owasp.esapi.waf.actions.Action;
import org.owasp.esapi.waf.actions.DoNothingAction;
import org.owasp.esapi.waf.internal.InterceptingHTTPServletResponse;

/**
 * This is the Rule subclass executed for &lt;add-secure-flag&gt; rules.
 * @author Arshan Dabirsiaghi
 *
 */
public class AddSecureFlagRule extends Rule {

    private List<Pattern> name;

    public AddSecureFlagRule(String id, List<Pattern> name) {
        this.name = name;
        setId(id);
    }

    public Action check(HttpServletRequest request,
            InterceptingHTTPServletResponse response,
            HttpServletResponse httpResponse) {

        DoNothingAction action = new DoNothingAction();

        return action;
    }

    public boolean doesCookieMatch(String cookieName) {

        for(int i=0;i<name.size();i++) {
            Pattern p = name.get(i);
            if ( p.matcher(cookieName).matches() ) {
                return true;
            }
        }

        return false;
    }

}
