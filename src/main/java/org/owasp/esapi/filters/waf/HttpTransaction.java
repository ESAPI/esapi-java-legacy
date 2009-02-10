/*
 * OWASP ESAPI WAF
 *
 * ModSecurity for Java M3 (Milestone 3)
 * Copyright (c) 2004-2005 Ivan Ristic <ivanr@webkreator.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

package org.owasp.esapi.filters.waf;

import java.io.IOException;

import javax.servlet.*;
import javax.servlet.http.*;

public class HttpTransaction {

    private boolean isRelevant = false;

    private ModSecurity modSecurity;

    public HttpServletRequest req;

    public HttpServletResponse res;

    public MsHttpServletRequest msReq;

    public MsHttpServletResponse msRes;

    public HttpTransaction(ModSecurity modSecurity, ServletRequest req, ServletResponse res) {
        this.modSecurity = modSecurity;
        this.req = (HttpServletRequest)req;
        this.res = (HttpServletResponse)res;
        this.msReq = new MsHttpServletRequest(this.req);
        this.msRes = new MsHttpServletResponse(this.res);
    }

    public void destroy() throws IOException {
        msRes.destroy();
        msReq.destroy();
    }

    // TODO allow logging prefix to be set

    public void log(int level, String msg) {
        // TODO add request info to the message
        String newMsg = msg;
        modSecurity.log(level, newMsg);
    }

    public boolean isRelevant() {
        return isRelevant;
    }

    public void setRelevant(boolean isRelevant) {
        this.isRelevant = isRelevant;
    }
}