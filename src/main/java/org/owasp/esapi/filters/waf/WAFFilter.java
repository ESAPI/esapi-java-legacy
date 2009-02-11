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

import java.io.File;
import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.UnavailableException;

import org.owasp.esapi.filters.waf.jak.*;

public class WAFFilter implements Filter {

    private FilterConfig filterConfig;

    private ModSecurity modSecurity;

    private String confFilename;

    private String securityErrorPage = null;

    private long confTime;

    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {

        // reload the configuration if necessary

        // TODO we need to be able to ask ModSecurity whether
        // its configuration has chaned. Configuration usually
        // consists of many files and don't know about them.
        //
        // TODO provide a way to reload configuration on-demand
        //
        // TODO plus a parameter to determine how long to wait
        // between two automatic checks
        //
        // TODO why not check in a separate thread of execution?

        if (new File(confFilename).lastModified() > confTime) {
            ModSecurity newModSecurity = null;
            try {
                newModSecurity = initModSecurity(confFilename,securityErrorPage);
            } catch(ServletException se) {
                se.printStackTrace(System.err);
            }
            // only reload if the new configuration is valid
            if (newModSecurity != null) {
                modSecurity = newModSecurity;
                confTime = new File(confFilename).lastModified();
            }
        }

        HttpTransaction tran = modSecurity.initRequest(req, res);

        try {
            // if ModSecurity returns false here processing
            // should stop
            int rc = modSecurity.processBefore(tran);
            if (rc == Inspector.ACTION_STOP) return;

            chain.doFilter(tran.msReq, tran.msRes);

            if (rc != Inspector.ACTION_ALLOW) {
                modSecurity.processAfter(tran);
            }
        } catch (IOException io) {
            // System.err.println("IOException raised in ModSecurityFilter");
            // io.printStackTrace(System.err);
        } catch (ServletException se) {
            // System.err.println("ServletException raised in ModSecurityFilter");
            // se.printStackTrace(System.err);
        } finally {
            modSecurity.processLogging(tran);
            tran.destroy();
        }

        // TODO implement a counter system to keep track of
        // how many transactions are using an ModSecurity instance
        // so we can safely destroy an engine that is not needed
        // any more
    }

    public void init(FilterConfig filterConfig) throws ServletException {
        this.filterConfig = filterConfig;

        confFilename = filterConfig.getInitParameter("conf");
        if (confFilename == null) throw new ServletException("ModSecurityFilter: parameter 'conf' not available");
        else confFilename = filterConfig.getServletContext().getRealPath(confFilename);

        securityErrorPage = filterConfig.getInitParameter("security_page");
        if (securityErrorPage != null){

        	if ( ! new File(filterConfig.getServletContext().getRealPath(securityErrorPage)).exists() ) {
        		throw new ServletException("ModSecurityFilter: parameter 'security_page' did not point to a real file. Resolved path: [" + securityErrorPage + "]");
        	}
        }

        modSecurity = initModSecurity(confFilename, securityErrorPage);
        confTime = new File(confFilename).lastModified();
    }

    public ModSecurity initModSecurity(String confFilename, String securityErrorPage) throws ServletException {
        ModSecurity modSecurity = new ModSecurity(filterConfig);
        try {
            modSecurity.registerModule("ModSecurity", modSecurity);
            modSecurity.addProvider(new FileDirectiveProvider(confFilename));
            modSecurity.setSecurityErrorPage(securityErrorPage);
            modSecurity.processConfiguration();
            modSecurity.doPostInit();
            modSecurity.doStart();
        } catch(Exception e) {
            throw new UnavailableException("ModSecurity initialization failed: " + e.getMessage());
        }
        return modSecurity;
    }

    public void destroy() {
        try {
            modSecurity.doStop();
            modSecurity.doDestroy();
        } catch(Exception e) {
            e.printStackTrace(System.err);
        }
    }
}
