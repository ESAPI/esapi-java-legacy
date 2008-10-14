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
 * the various applicaton layers. This class provides access control for URLs, business functions, data, services, and
 * files.
 * <P>
 * <img src="doc-files/AccessController.jpg" height="600">
 * <P>
 * The implementation of this interface will need to access some sort of user information repository to determine what
 * roles or permissions are assigned to the accountName passed into the various methods. In addition, the implementation
 * will also need information about the resources that are being accessed. Using the user information and the resource
 * information, the implementation should return an access control decision. 
 * <P>
 * Implementers are encouraged to build on existing access control mechanisms, such as methods like isUserInRole() or
 * hasPrivilege(). While powerful, these methods can be confusing, as users may be in multiple roles or possess multiple
 * overlapping privileges. These methods encourage the use of complex boolean tests throughout the code. The point of
 * this interface is to centralize access control logic so that it is easy to use and easy to verify.
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
     * The implementation of this method should call assertAuthorizedForURL(String url), and if an AccessControlException is not thrown, this method should
     * return true.
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
     * The implementation of this method should call assertAuthorizedForFunction(String functionName), and if an AccessControlException is not thrown, this method should
     * return true.
     * 
     * @param functionName 
     * 		the function name
     * 
     * @return 
     * 		true, if is authorized for function
     */
    boolean isAuthorizedForFunction(String functionName);

    /**
     * Checks if an account is authorized to access the referenced data. 
     * 
     * The implementation of this method should call assertAuthorizedForData(String key), and if an AccessControlException is not thrown, this method should
     * return true.
     * 
     * @param key 
     * 		the key
     * 
     * @return 
     * 		true, if is authorized for data
     */
    boolean isAuthorizedForData(String key);

    boolean isAuthorizedForData(String action, Object data);
    
    /**
     * Checks if an account is authorized to access the referenced file. 
     * 
     * The implementation of this method should call assertAuthorizedForFile(String filepath), and if an AccessControlException is not thrown, this method should
     * return true.
     *   
     * @param filepath 
     * 		the path of the file to be checked, including filename
     * 
     * @return 
     * 		true, if is authorized for file
     */
    boolean isAuthorizedForFile(String filepath);

    /**
     * Checks if an account is authorized to access the referenced service. This can be used in applications that
     * provide access to a variety of backend services.
     * 
     * The implementation of this method should call assertAuthorizedForService(String serviceName), and if an AccessControlException is not thrown, this method should
     * return true.
     * 
     * @param serviceName 
     * 		the service name
     * 
     * @return 
     * 		true, if is authorized for service
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
     * 
     * Specification:  The implementation should do the following:
     * 	1) Check to see if the resource exists and if not, throw an AccessControlException
     * 	2) Use available information to make an access control decision	
     * 		a. Ideally, this policy would be data driven
     * 		b. You can use the current User, roles, data type, data name, time of day, etc.
     *  	c. Access control decisions must deny by default
     * 	3) If access is not permitted, throw AccessControlException with details
     * 
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
     * 
     * This method throws an AccessControlException if access is not authorized, or if the referenced function does not exist.
     * If the User is authorized, this method simply returns.
     * 
     * Specification:  The implementation should do the following:
     * 	1) Check to see if the function exists and if not, throw an AccessControlException
     * 	2) Use available information to make an access control decision	
     * 		a. Ideally, this policy would be data driven
     * 		b. You can use the current User, roles, data type, data name, time of day, etc.
     * 		c. Access control decisions must deny by default
     * 	3) If access is not permitted, throw AccessControlException with details
     *   
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
     * 
     * Specification:  The implementation should do the following:
     * 	1) Check to see if the resource exists and if not, throw an AccessControlException
     * 	2) Use available information to make an access control decision	
     * 		a. Ideally, this policy would be data driven
     * 		b. You can use the current User, roles, data type, data name, time of day, etc.
     * 		c. Access control decisions must deny by default
     * 	3) If access is not permitted, throw AccessControlException with details
     *  
     * @param key 
     * 		the name of the target data object
     * 
     * @throws AccessControlException 
     * 		if access is not permitted
     */
    void assertAuthorizedForData(String key) throws AccessControlException;
    
    /*
     * Javadocs here
     * 
     */
    void assertAuthorizedForData(String action, Object data) throws AccessControlException;
   
    /**
     * Checks if an account is authorized to access the referenced file. The implementation should validate and canonicalize the 
     * input to be sure the filepath is not malicious.
     * 
     * This method throws an AccessControlException if access is not authorized, or if the referenced File does not exist.
     * If the User is authorized, this method simply returns.
     * 
     * Specification:  The implementation should do the following:
     * 	1) Check to see if the File exists and if not, throw an AccessControlException
     * 	2) Use available information to make an access control decision	
     * 		a. Ideally, this policy would be data driven
     * 		b. You can use the current User, roles, data type, data name, time of day, etc.
     *  	c. Access control decisions must deny by default
     * 	3) If access is not permitted, throw AccessControlException with details
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
     * 
     * This method throws an AccessControlException if access is not authorized, or if the referenced service does not exist.
     * If the User is authorized, this method simply returns.
     * 
     * Specification:  The implementation should do the following:
     * 	1) Check to see if the service exists and if not, throw an AccessControlException
     * 	2) Use available information to make an access control decision	
     * 		a. Ideally, this policy would be data driven
     * 		b. You can use the current User, roles, data type, data name, time of day, etc.
     *  	c. Access control decisions must deny by default
     * 	3) If access is not permitted, throw AccessControlException with details
     * 
     * @param serviceName 
     * 		the service name
     * 
     * @throws AccessControlException
     * 		if access is not permitted
     */				
    void assertAuthorizedForService(String serviceName) throws AccessControlException;
    
    
}
