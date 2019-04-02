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
package org.owasp.esapi;

import org.owasp.esapi.errors.AccessControlException;



/**
 * The AccessController interface defines a set of methods that can be used in a wide variety of applications to
 * enforce access control. In most applications, access control must be performed in multiple different locations across
 * the various application layers. This class provides access control for URLs, business functions, data, services, and
 * files.
 * <P>
 * The implementation of this interface will need to access the current User object (from Authenticator.getCurrentUser())
 * to determine roles or permissions. In addition, the implementation
 * will also need information about the resources that are being accessed. Using the user information and the resource
 * information, the implementation should return an access control decision. 
 * <P>
 * Implementers are encouraged to implement the ESAPI access control rules, like assertAuthorizedForFunction() using 
 * existing access control mechanisms, such as methods like isUserInRole() or hasPrivilege(). While powerful, 
 * methods like isUserInRole() can be confusing for developers, as users may be in multiple roles or possess multiple 
 * overlapping privileges. Direct use of these finer grained access control methods encourages the use of complex boolean 
 * tests throughout the code, which can easily lead to developer mistakes.
 * <P>
 * The point of the ESAPI access control interface is to centralize access control logic behind easy to use calls like 
 * assertAuthorized() so that access control is easy to use and easy to verify. Here is an example of a very 
 * straightforward to implement, understand, and verify ESAPI access control check: 
 * 
 * <pre>
 * try {
 *     ESAPI.accessController().assertAuthorized("businessFunction", runtimeData);
 *     // execute BUSINESS_FUNCTION
 * } catch (AccessControlException ace) {
 * ... attack in progress
 * }
 * </pre>
 * 
 * Note that in the user interface layer, access control checks can be used to control whether particular controls are
 * rendered or not. These checks are supposed to fail when an unauthorized user is logged in, and do not represent
 * attacks. Remember that regardless of how the user interface appears, an attacker can attempt to invoke any business
 * function or access any data in your application. Therefore, access control checks in the user interface should be
 * repeated in both the business logic and data layers.
 * 
 * <pre>
 * &lt;% if ( ESAPI.accessController().isAuthorized( "businessFunction", runtimeData ) ) { %&gt;
 * &lt;a href=&quot;/doAdminFunction&quot;&gt;ADMIN&lt;/a&gt;
 * &lt;% } else { %&gt;
 * &lt;a href=&quot;/doNormalFunction&quot;&gt;NORMAL&lt;/a&gt;
 * &lt;% } %&gt;
 * </pre>
 * 
 * @author Mike H. Fauzy (mike.fauzy@aspectsecurity.com) ESAPI v1.6-
 * @author Jeff Williams (jeff.williams@aspectsecurity.com) ESAPI v0-1.5
 */
public interface AccessController {

	/**
	 * <code>isAuthorized</code> executes the <code>AccessControlRule</code> 
	 * that is identified by <code>key</code> and listed in the 
	 * <code>resources/ESAPI-AccessControlPolicy.xml</code> file. It returns 
	 * true if the <code>AccessControlRule</code> decides that the operation 
	 * should be allowed. Otherwise, it returns false. Any exception thrown by 
	 * the <code>AccessControlRule</code> must result in false. If 
	 * <code>key</code> does not map to an <code>AccessControlRule</code>, then 
	 * false is returned. 
	 *  
	 * Developers should call isAuthorized to control execution flow. For 
	 * example, if you want to decide whether to display a UI widget in the 
	 * browser using the same logic that you will use to enforce permissions
	 * on the server, then isAuthorized is the method that you want to use.
	 * 
	 * Typically, assertAuthorized should be used to enforce permissions on the 
	 * server.
	 *  
	 * @param key <code>key</code> maps to 
	 * <code>&lt;AccessControlPolicy&gt;&lt;AccessControlRules&gt;
	 *     &lt;AccessControlRule name="key"</code>
	 * @param runtimeParameter runtimeParameter can contain anything that 
	 *        the AccessControlRule needs from the runtime system. 
	 * @return Returns <code>true</code> if and only if the AccessControlRule specified 
	 *        by <code>key</code> exists and returned <code>true</code>. 
	 *        Otherwise returns <code>false</code> 
	 */
	public boolean isAuthorized(Object key, Object runtimeParameter);
	
	/**
	 * <code>assertAuthorized</code> executes the <code>AccessControlRule</code> 
	 * that is identified by <code>key</code> and listed in the 
	 * <code>resources/ESAPI-AccessControlPolicy.xml</code> file. It does 
	 * nothing if the <code>AccessControlRule</code> decides that the operation 
	 * should be allowed. Otherwise, it throws an 
	 * <code>org.owasp.esapi.errors.AccessControlException</code>. Any exception
	 * thrown by the <code>AccessControlRule</code> will also result in an 
	 * <code>AccesControlException</code>. If <code>key</code> does not map to 
	 * an <code>AccessControlRule</code>, then an <code>AccessControlException
	 * </code> is thrown.  
	 *  
	 * Developers should call {@code assertAuthorized} to enforce privileged access to 
	 * the system. It should be used to answer the question: "Should execution 
	 * continue." Ideally, the call to <code>assertAuthorized</code> should
	 * be integrated into the application framework so that it is called 
	 * automatically. 
	 *  
	 * @param key <code>key</code> maps to 
	 * &lt;AccessControlPolicy&gt;&lt;AccessControlRules&gt;
	 *     &lt;AccessControlRule name="key"
	 * @param runtimeParameter runtimeParameter can contain anything that 
	 *        the AccessControlRule needs from the runtime system.
	 */
	public void assertAuthorized(Object key, Object runtimeParameter)
		throws AccessControlException;

		

	
	/*** Below this line has been deprecated as of ESAPI 1.6 ***/ 
	
	
	
	
    /**
     * Checks if the current user is authorized to access the referenced URL. Generally, this method should be invoked in the
     * application's controller or a filter as follows:
     * <PRE>ESAPI.accessController().isAuthorizedForURL(request.getRequestURI().toString());</PRE>
     * 
     * The implementation of this method should call assertAuthorizedForURL(String url), and if an AccessControlException is 
     * not thrown, this method should return true. This way, if the user is not authorized, false would be returned, and the 
     * exception would be logged.
     * 
     * @param url 
     * 		the URL as returned by request.getRequestURI().toString()
     * 
     * @return 
     * 		true, if is authorized for URL
     */
    @Deprecated
    boolean isAuthorizedForURL(String url);

    /**
     * Checks if the current user is authorized to access the referenced function. 
     * 
     * The implementation of this method should call assertAuthorizedForFunction(String functionName), and if an 
     * AccessControlException is not thrown, this method should return true.
     * 
     * @param functionName 
     * 		the name of the function
     * 
     * @return 
     * 		true, if is authorized for function
     */
    @Deprecated
    boolean isAuthorizedForFunction(String functionName);


    /**
     * Checks if the current user is authorized to access the referenced data, represented as an Object. 
     * 
     * The implementation of this method should call assertAuthorizedForData(String action, Object data), and if an 
     * AccessControlException is not thrown, this method should return true.
     * 
     * @param action
     *      The action to verify for an access control decision, such as a role, or an action being performed on the object 
     *      (e.g., Read, Write, etc.), or the name of the function the data is being passed to.
     * 
     * @param data
     * 		The actual object or object identifier being accessed or a reference to the object being accessed.
     * 
     * @return 
     * 		true, if is authorized for the data
     */
    @Deprecated
    boolean isAuthorizedForData(String action, Object data);
    
    /**
     * Checks if the current user is authorized to access the referenced file. 
     * 
     * The implementation of this method should call assertAuthorizedForFile(String filepath), and if an AccessControlException 
     * is not thrown, this method should return true.
     *   
     * @param filepath 
     * 		the path of the file to be checked, including filename
     * 
     * @return 
     * 		true, if is authorized for the file
     */
    @Deprecated
    boolean isAuthorizedForFile(String filepath);

    /**
     * Checks if the current user is authorized to access the referenced service. This can be used in applications that
     * provide access to a variety of back end services.
     * 
     * The implementation of this method should call assertAuthorizedForService(String serviceName), and if an 
     * AccessControlException is not thrown, this method should return true.
     * 
     * @param serviceName 
     * 		the service name
     * 
     * @return 
     * 		true, if is authorized for the service
     */
    @Deprecated
    boolean isAuthorizedForService(String serviceName);

    /**
     * Checks if the current user is authorized to access the referenced URL. The implementation should allow
     * access to be granted to any part of the URL. Generally, this method should be invoked in the
     * application's controller or a filter as follows:
     * <PRE>ESAPI.accessController().assertAuthorizedForURL(request.getRequestURI().toString());</PRE> 
     * 
     * This method throws an AccessControlException if access is not authorized, or if the referenced URL does not exist.
     * If the User is authorized, this method simply returns.
     * <P>
     * Specification:  The implementation should do the following:
     * <ol>
     * <li>Check to see if the resource exists and if not, throw an AccessControlException</li>
     * <li>Use available information to make an access control decision</li>
     *      <ol type="a">
     *      <li>Ideally, this policy would be data driven</li>
     * 		<li>You can use the current User, roles, data type, data name, time of day, etc.</li>
     *  	<li>Access control decisions must deny by default</li>
     *      </ol>
     * <li>If access is not permitted, throw an AccessControlException with details</li>
     * </ol> 
     * @param url 
     * 		the URL as returned by request.getRequestURI().toString()
     * 
     * @throws AccessControlException 
     * 		if access is not permitted
     */
    @Deprecated
    void assertAuthorizedForURL(String url) throws AccessControlException;
    
    /**
     * Checks if the current user is authorized to access the referenced function. The implementation should define the
     * function "namespace" to be enforced. Choosing something simple like the class name of action classes or menu item
     * names will make this implementation easier to use.
     * <P>
     * This method throws an AccessControlException if access is not authorized, or if the referenced function does not exist.
     * If the User is authorized, this method simply returns.
     * <P>
     * Specification:  The implementation should do the following:
     * <ol>
     * <li>Check to see if the function exists and if not, throw an AccessControlException</li>
     * <li>Use available information to make an access control decision</li>
     *      <ol type="a">
     *      <li>Ideally, this policy would be data driven</li>
     * 		<li>You can use the current User, roles, data type, data name, time of day, etc.</li>
     *  	<li>Access control decisions must deny by default</li>
     *      </ol>
     * <li>If access is not permitted, throw an AccessControlException with details</li>
     * </ol> 
     * 
     * @param functionName 
     * 		the function name
     * 
     * @throws AccessControlException 
     * 		if access is not permitted
     */
    @Deprecated
    void assertAuthorizedForFunction(String functionName) throws AccessControlException;
    

    /**
     * Checks if the current user is authorized to access the referenced data.  This method simply returns if access is authorized.  
     * It throws an AccessControlException if access is not authorized, or if the referenced data does not exist.
     * <P>
     * Specification:  The implementation should do the following:
     * <ol>
     * <li>Check to see if the resource exists and if not, throw an AccessControlException</li>
     * <li>Use available information to make an access control decision</li>
     *      <ol type="a">
     *      <li>Ideally, this policy would be data driven</li>
     * 		<li>You can use the current User, roles, data type, data name, time of day, etc.</li>
     *  	<li>Access control decisions must deny by default</li>
     *      </ol>
     * <li>If access is not permitted, throw an AccessControlException with details</li>
     * </ol> 
     * 
     * @param action
     *      The action to verify for an access control decision, such as a role, or an action being performed on the object 
     *      (e.g., Read, Write, etc.), or the name of the function the data is being passed to.
     * 
     * @param data
     * 		The actual object or object identifier being accessed or a reference to the object being accessed.
     * 
     * @throws AccessControlException 
     * 		if access is not permitted
     */
    @Deprecated
    void assertAuthorizedForData(String action, Object data) throws AccessControlException;
   
    /**
     * Checks if the current user is authorized to access the referenced file. The implementation should validate and canonicalize the 
     * input to be sure the filepath is not malicious.
     * <P>
     * This method throws an AccessControlException if access is not authorized, or if the referenced File does not exist.
     * If the User is authorized, this method simply returns.
     * <P>
     * Specification:  The implementation should do the following:
     * <ol>
     * <li>Check to see if the File exists and if not, throw an AccessControlException</li>
     * <li>Use available information to make an access control decision</li>
     *      <ol type="a">
     *      <li>Ideally, this policy would be data driven</li>
     * 		<li>You can use the current User, roles, data type, data name, time of day, etc.</li>
     *  	<li>Access control decisions must deny by default</li>
     *      </ol>
     * <li>If access is not permitted, throw an AccessControlException with details</li>
     * </ol> 
     * 
     * @param filepath
     * 			Path to the file to be checked
     * @throws AccessControlException if access is denied
     */
    @Deprecated
    void assertAuthorizedForFile(String filepath) throws AccessControlException;
    
    /**
     * Checks if the current user is authorized to access the referenced service. This can be used in applications that
     * provide access to a variety of backend services.
     * <P>
     * This method throws an AccessControlException if access is not authorized, or if the referenced service does not exist.
     * If the User is authorized, this method simply returns.
     * <P>
     * Specification:  The implementation should do the following:
     * <ol>
     * <li>Check to see if the service exists and if not, throw an AccessControlException</li>
     * <li>Use available information to make an access control decision</li>
     *      <ol type="a">
     *      <li>Ideally, this policy would be data driven</li>
     * 		<li>You can use the current User, roles, data type, data name, time of day, etc.</li>
     *  	<li>Access control decisions must deny by default</li>
     *      </ol>
     * <li>If access is not permitted, throw an AccessControlException with details</li>
     * </ol> 
     * 
     * @param serviceName 
     * 		the service name
     * 
     * @throws AccessControlException
     * 		if access is not permitted
     */				
    @Deprecated
    void assertAuthorizedForService(String serviceName) throws AccessControlException;
    
}
