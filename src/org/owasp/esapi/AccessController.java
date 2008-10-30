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
 * <img src="doc-files/AccessController.jpg">
 * <P>
 * The implementation of this interface will need to access the current User object (from Authenticator.getCurrentUser())
 * to determine roles or permissions. In addition, the implementation
 * will also need information about the resources that are being accessed. Using the user information and the resource
 * information, the implementation should return an access control decision. 
 * <P>
 * Implementers are encouraged to implement the ESAPI access control methods, like assertAuthorizedForFunction() using 
 * existing access control mechanisms, such as methods like isUserInRole() or hasPrivilege(). While powerful, 
 * methods like isUserInRole() can be confusing for developers, as users may be in multiple roles or possess multiple 
 * overlapping privileges. Direct use of these finer grained access control methods encourages the use of complex boolean 
 * tests throughout the code, which can easily lead to developer mistakes.
 * <P>
 * The point of the ESAPI access control interface is to centralize access control logic behind easy to use calls like 
 * assertAuthorizedForData() so that access control is easy to use and easy to verify. Here is an example of a very 
 * straightforward to implement, understand, and verify ESAPI access control check: 
 * 
 * <pre>
 * try {
 *     ESAPI.accessController().assertAuthorizedForFunction( BUSINESS_FUNCTION );
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
 * &lt;% if ( ESAPI.accessController().isAuthorizedForFunction( ADMIN_FUNCTION ) ) { %&gt;
 * &lt;a href=&quot;/doAdminFunction&quot;&gt;ADMIN&lt;/a&gt;
 * &lt;% } else { %&gt;
 * &lt;a href=&quot;/doNormalFunction&quot;&gt;NORMAL&lt;/a&gt;
 * &lt;% } %&gt;
 * </pre>
 * 
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 */
public interface AccessController {

    /**
     * Checks if an account is authorized to access the referenced URL. Generally, this method should be invoked in the
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
    boolean isAuthorizedForURL(String url);

    /**
     * Checks if an account is authorized to access the referenced function. 
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
    boolean isAuthorizedForFunction(String functionName);

    /**
     * Checks if an account is authorized to access the referenced data, represented as a String. 
     * 
     * The implementation of this method should call assertAuthorizedForData(String key), and if an AccessControlException 
     * is not thrown, this method should return true.
     * 
     * @param key 
     * 		the name of the referenced data object
     * 
     * @return 
     * 		true, if is authorized for the data
     */
    boolean isAuthorizedForData(String key);

    /**
     * Checks if an account is authorized to access the referenced data, represented as an Object. 
     * 
     * The implementation of this method should call assertAuthorizedForData(String action, Object data), and if an 
     * AccessControlException is not thrown, this method should return true.
     * 
     * @param action
     * 		the action to check for in the configuration file in the resource directory
     * 
     * @param data
     * 		the data to check for in the configuration file in the resource directory 	
     * 
     * @return 
     * 		true, if is authorized for the data
     */
    boolean isAuthorizedForData(String action, Object data);
    
    /**
     * Checks if an account is authorized to access the referenced file. 
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
    boolean isAuthorizedForFile(String filepath);

    /**
     * Checks if an account is authorized to access the referenced service. This can be used in applications that
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
    boolean isAuthorizedForService(String serviceName);

    /**
     * Checks if an account is authorized to access the referenced URL. The implementation should allow
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
    void assertAuthorizedForURL(String url) throws AccessControlException;
    
    /**
     * Checks if an account is authorized to access the referenced function. The implementation should define the
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
     * @param key 
     * 		the name of the target data object
     * 
     * @throws AccessControlException 
     * 		if access is not permitted
     */
    void assertAuthorizedForData(String key) throws AccessControlException;
    
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
     * 		the action to check for in the configuration file in the resource directory
     * 
     * @param data
     * 		the data to check for in the configuration file in the resource directory
     * 
     * @throws AccessControlException 
     * 		if access is not permitted
     */
    void assertAuthorizedForData(String action, Object data) throws AccessControlException;
   
    /**
     * Checks if an account is authorized to access the referenced file. The implementation should validate and canonicalize the 
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
     * @see org.owasp.esapi.Encoder#canonicalize(String)
     * 
     * @param filepath 
     * 		the path of the file to be checked, including filename
     * 
     * @throws AccessControlException 
     * 		if access is not permitted
     */
    void assertAuthorizedForFile(String filepath) throws AccessControlException;
    
    /**
     * Checks if an account is authorized to access the referenced service. This can be used in applications that
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
    void assertAuthorizedForService(String serviceName) throws AccessControlException;
    
    
}
