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

import org.owasp.esapi.errors.EnterpriseSecurityException;

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
			logger.logSuccess(Logger.SECURITY, "Invoking function: " + function );
			if ( function == null ) {
				FunctionUpdateUsermap.invoke();
			} else if ( function.equalsIgnoreCase( "create" ) ) {
				FunctionCreateUser.invoke();
			} else if ( function.equalsIgnoreCase( "delete" ) ) {
				FunctionDeleteUser.invoke();
			} else if ( function.equalsIgnoreCase( "enable" ) ) {
				FunctionEnableUser.invoke();
			} else if ( function.equalsIgnoreCase( "disable" ) ) {
				FunctionDisableUser.invoke();
			} else if ( function.equalsIgnoreCase( "lock" ) ) {
				FunctionLockUser.invoke();
			} else if ( function.equalsIgnoreCase( "unlock" ) ) {
				FunctionUnlockUser.invoke();
			} else if ( function.equalsIgnoreCase( "password" ) ) {
				FunctionChangePassword.invoke();
			} else if ( function.equalsIgnoreCase( "logout" ) ) {
				FunctionLogout.invoke();
				RequestDispatcher dispatcher = request.getRequestDispatcher("WEB-INF/login.jsp");
				dispatcher.forward(request, response);
				return;
			}
			RequestDispatcher dispatcher = request.getRequestDispatcher("WEB-INF/index.jsp");
			dispatcher.forward(request, response);
		} catch ( EnterpriseSecurityException e ) {
			e.printStackTrace( response.getWriter() );
			// try {
			//	HTTPUtilities.getInstance().sendSafeForward("Controller", "WEB-INF/security.jsp");
			// } catch( Exception ex ) {
			//	throw new ServletException( "FIXME" );
			//}
		}
	}

}
