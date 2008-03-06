/**
 * 
 */
package org.owasp.esapi;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.owasp.esapi.errors.AuthenticationException;
import org.owasp.esapi.errors.EnterpriseSecurityException;
import org.owasp.esapi.errors.ValidationException;

/**
 * @author jwilliams
 */
public class Controller extends HttpServlet {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	protected static final Logger logger = Logger.getLogger("ESAPI", "TestServlet");
	
    public void init(ServletConfig config) {
    	// no parameters in web.xml
    }

    /*
	 * (non-Javadoc)
	 * 
	 * @see javax.servlet.http.HttpServlet#doGet(javax.servlet.http.HttpServletRequest,
	 *      javax.servlet.http.HttpServletResponse)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		doPost(request, response);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see javax.servlet.http.HttpServlet#doPost(javax.servlet.http.HttpServletRequest,
	 *      javax.servlet.http.HttpServletResponse)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		try {
			
			String function = request.getParameter("function");
			
			if ( function != null && function.equalsIgnoreCase( "logout" ) ) {
				FunctionLogout.invoke();
				RequestDispatcher dispatcher = request.getRequestDispatcher("WEB-INF/login.jsp");
				dispatcher.forward(request, response);
				return;
			}
		
						
			// Functions that require admin authorization

			// Perform authorization check
			// FIXME - this should be in ESAPI config, enforced by ESAPIFilter using isAuthorized.
			// Note: Since these are single-role functions, a centralized authorization check is appropriate.
			// If these functions were "multi-role" then the isAuthorized call should go in each function.
			
			if ( !ESAPI.authenticator().getCurrentUser().isInRole("admin")) {
				FunctionLogout.invoke();
				request.setAttribute("message", "Authentication failed" );
				RequestDispatcher dispatcher = request.getRequestDispatcher("WEB-INF/login.jsp");
				dispatcher.forward(request, response);
				return;
			}
			
			
			// Functions that do not require authorization
			if ( function == null ) {
				FunctionUpdateUsermap.invoke();
			} else if ( function.equalsIgnoreCase( "create" ) ) {
				FunctionCreateUser.invoke();
			} else if ( function.equalsIgnoreCase( "delete" ) ) {
				FunctionDeleteUser.invoke();
			} else if ( function.equalsIgnoreCase( "enable" ) ) {
				FunctionEnableUser.invoke();
			} else if ( function.equalsIgnoreCase( "update" ) ) {
				FunctionUpdatePassword.invoke();
			} else if ( function.equalsIgnoreCase( "disable" ) ) {
				FunctionDisableUser.invoke();
			} else if ( function.equalsIgnoreCase( "lock" ) ) {
				FunctionLockUser.invoke();
			} else if ( function.equalsIgnoreCase( "unlock" ) ) {
				FunctionUnlockUser.invoke();
			} else if ( function.equalsIgnoreCase( "password" ) ) {
				FunctionChangePassword.invoke();
			} else {
				throw new ValidationException( "Invalid function", "User entered an invalid function: " + function );
			}
			
		} catch ( EnterpriseSecurityException e ) {
			request.setAttribute("message", "SECURITY: " + e.getUserMessage() );
		} catch ( Exception e ) {
			logger.logError( Logger.SECURITY, e.getMessage(), e );
			request.setAttribute("message", "ERROR" );
		}
		// FIXME: this should be automatic inside Authenticator/User somehow.
		try {
			Authenticator auth = (Authenticator)ESAPI.authenticator();
			auth.saveUsers();
		} catch( AuthenticationException e ) {
			request.setAttribute( "message", e.getUserMessage() );
		}
		RequestDispatcher dispatcher = request.getRequestDispatcher("WEB-INF/index.jsp");
		dispatcher.forward(request, response);
	}

}
