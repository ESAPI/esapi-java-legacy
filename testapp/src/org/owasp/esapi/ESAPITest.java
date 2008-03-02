/**
 * 
 */
package org.owasp.esapi;

import java.io.IOException;
import java.util.Arrays;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.owasp.esapi.errors.EnterpriseSecurityException;
import org.owasp.esapi.errors.IntrusionException;

/**
 * @author jwilliams
 */
public class ESAPITest extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private static final Logger logger = Logger.getLogger("ESAPI", "ESAPITest");

    public void init(ServletConfig config) {
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        doPost(request, response);
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.http.HttpServlet#doPost(javax.servlet.http.HttpServletRequest,
     * javax.servlet.http.HttpServletResponse)
     */
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

        // set current user or show login page       
        User user = null;
        try {
            user = ESAPI.authenticator().login(request, response);
        } catch (EnterpriseSecurityException e) {
            response.getWriter().write( "<FORM method=\"POST\" action=\"test\">username: <INPUT name=\"username\"><br><br>password: <INPUT type=\"password\" name=\"password\"><br><br><BUTTON type='submit'>login</BUTTON></FORM>" );
            return;
        }

        // Help the browser enforce security
        ESAPI.httpUtilities().setNoCacheHeaders();
        ESAPI.httpUtilities().safeSetContentType();
        
        response.getWriter().write( "<HTML><HEAD><TITLE>ESAPI Test Servlet</TITLE></HEAD><HTML><BODY>" );
        
        // global request validation - write out errors instead of forwarding to error page
        try {
        	ESAPI.httpUtilities().verifyCSRFToken();
        } catch( IntrusionException e ) {
            response.getWriter().write( "<P>Invalid HTTP Request - Missing CSRF Token</P>" );
        }
        
        if ( !ESAPI.validator().isValidHTTPRequest(request) ) {
            response.getWriter().write( "<P>Invalid HTTP Request - Invalid Characters</P>" );
        }
        
        response.getWriter().write("<HR>");
                
        
        // FIXME: AAA need access control check

        // Perform business function
        String input = request.getParameter("param");
        if (input != null) {
            if (!ESAPI.validator().isValidDataFromBrowser("param", "SafeString", input)) {
                response.getWriter().write("Invalid: " + ESAPI.encoder().encodeForHTML(input) + "<br>");
            } else {
                response.getWriter().write("Valid: " + ESAPI.encoder().encodeForHTML(input) + "<br>");
            }
            if (input.equals("logout")) {
                user.logout();
            }
        }

        if ( user != null ) {
            response.getWriter().write("<b>User: " + user.getAccountName() + "</b><br>");
            response.getWriter().write("  Last Host: " + user.getLastHostAddress() + "<br>");
            response.getWriter().write("  Last Login Failure: " + user.getLastFailedLoginTime() + "<br>");
            response.getWriter().write("  Last Login: " + user.getLastLoginTime() + "<br>");
            response.getWriter().write("  Roles: " + user.getRoles() + "<br>");
            response.getWriter().write("<br>");
            response.getWriter().write("<br>");
        }
        
        String valid = ESAPI.httpUtilities().addCSRFToken("/ESAPITest/test?param=test");
        response.getWriter().write("  <a href=\""+ valid +"\">valid</a><br>");
        String invalid = ESAPI.httpUtilities().addCSRFToken("/ESAPITest/test?param=test<script>alert()</script>");
        response.getWriter().write("  <a href=\""+ invalid +"\">invalid</a><br>");
        String logout = ESAPI.httpUtilities().addCSRFToken("/ESAPITest/test?param=logout");
        response.getWriter().write("  <a href=\""+ logout +"\">logout</a><br>");

        // Log the request, ignoring the password field
        String[] ignore = { "password" };
        logger.logHTTPRequest(Logger.SECURITY, request, Arrays.asList(ignore));

        response.getWriter().write( "</BODY></HTML>" );
    }

}
