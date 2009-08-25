/*
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2009 - The OWASP Foundation
 */
package org.owasp.esapi.util;

import org.owasp.esapi.errors.ConfigurationException;
// CHECKME: I thought this class could be generally useful so placed it in this
//			package rather than in somewhere under org.owasp.esapi.reference
//			(maybe a util package there), but if you want to move it to
//			somewhere that others won't be tempted to use it, I'm OK with that.
//			(BTW, where I work, we often have 'pvt' subpackages for private
//			implementation classes that we don't want clients to use _directly_.
//			They end up in the same jar file, but we simply exclude all the pvt
//			packages from the generated Javadoc.)
//
//			The reason I implemented this in the first place is I didn't like
//			all the repetitive code to do essentially what this class does.
//			Using this to refactor the org.owasp.esapi.ESAPI class eliminated
//			a lot of lines of code. Of course, I'm expecting this will all be
//			reviewed in some code inspection.		- kevin wall
/**
 * A generic object factory to create an object of class T. T must be a concrete
 * class that has a no-argument public constructor.
 * <p>
 * Typical use is something like:
 * <pre>
 * 		import com.example.interfaces.DrinkingEstablishment;
 * 		import com.example.interfaces.Beer;
 * 		...
 * 		// Typically these would be populated from some Java properties file
 * 		String barName = "com.example.foo.Bar";
 * 		String beerBrand = "com.example.brewery.Guiness";
 * 		...
 * 		DrinkingEstablishment bar =
 * 				(new ObjFactory<DrinkingEstablishment>()).make(barName, "DrinkingEstablishment");
 * 		Beer beer =
 * 				(new ObjFactory<Beer>()).make(beerBrand, "Beer");
 *		bar.drink(beer);	// Drink a Guiness beer at the foo Bar. :)
 *		...
 * </pre>
 * </p><p>
 *  Copyright (c) 2009 - The OWASP Foundation
 *  </p>
 * @author kevin.w.wall@gmail.com
 *
 * @param <T>	The type T for which the class name passed to <code>make</code>
 * 				is the same as T or a sub-type of T.
 */
public class ObjFactory<T> {
	// CHECKME: This is just some of the common code snippets from ESAPI refactored out.
	
	/**
	 * Create an object based on the <code>className</code> parameter.
	 * 
	 * @param className	The name of the class to construct. Should be a fully qualified name and
	 * 					generally the same as type <code>T</code>
	 * @param typeName	A type name used in error messages / exceptions.
	 * @return	An object of type <code>className</code>, which is cast to type <code>T</code>.
	 * @throws	ConfigurationException thrown if class name not found in class path, or does not
	 * 			have a public, no-argument constructor, or is not a concrete class, or if it is
	 * 			not a sub-type of <code>T</code> (or <code>T</code> itself). Usually this is
	 * 			caused by a misconfiguration of the class names specified in the ESAPI.properties
	 * 			file. Also thrown if the CTOR of the specified <code>className</code> throws
	 * 			an <code>Exception</code> of some type.
	 */
	@SuppressWarnings({ "unchecked" })	// Added because of Eclipse warnings, but ClassCastException IS caught.
	public T make(String className, String typeName) throws ConfigurationException {
		Object obj = null;
		String errMsg = null;
		try {
			if (null == className || "".equals(className) ) {
				throw new IllegalArgumentException("Classname cannot be null or empty.");
			}
			if (null == typeName || "".equals(typeName) ) {
				// No big deal...just use "[unknown?]" for this as it's only for an err msg.
				typeName = "[unknown?]";	// CHECKME: Any better suggestions?
			}
			
			Class<?> theClass = Class.forName(className);
// System.out.println("DEBUG: class=" + className + ", typeName=" + typeName + ": Passed Class.forName()");
			obj = theClass.newInstance();
// System.out.println("DEBUG: class=" + className + ", typeName=" + typeName + ": Passed Class.newInstance()");

			return (T)obj;		// Eclipse warning here if @SupressWarnings omitted.
			
			// CHECKME: If any of these exceptions occur, I would argue that in an Enterprise production
			// 			environment you _should_ throw some exception, even if it is an unchecked exception.
			//			Otherwise, the appl will likely get some other exception (possibly much later) which
			//			they are going to have to correlate to one of these outputs to STDOUT. Finally, if
			//			we are going to log WITHOUT a standard known logger, IMHO, it's better to log STDERR,
			//			which is at least unbuffered rather than sending to STDOUT which is buffered. (I have
			//			seen cases where the buffered output is lost if the JVM process dies because of an
			//			uncaught exception.) One catch-22 is if we want to use this in the ESAPI class to
			//			instantiate the Logger, what do we use for a Logger here since that may not have been
			//			done yet or may even be the part that fails.
			//  
			//			Finally, since this idiom occurs repetitively, I've refactored it to here.
			//
			// Good reference:
			//			http://java.sun.com/docs/books/tutorial/reflect/member/ctorTrouble.html
		} catch( IllegalArgumentException ex ) {
			errMsg = ex.toString() + " " + typeName + " type name cannot be null or empty.";
			System.out.println(errMsg);
			throw new ConfigurationException(errMsg, ex);
		}catch ( ClassNotFoundException ex ) {
			errMsg = ex.toString() + " " + typeName + " class (" + className + ") must be in class path.";
			System.out.println(errMsg);
			throw new ConfigurationException(errMsg, ex);
		} catch( InstantiationException ex ) {
			errMsg = ex.toString() + " " + typeName + " class (" + className + ") must be concrete.";
			System.out.println(errMsg);
			throw new ConfigurationException(errMsg, ex);
		} catch( IllegalAccessException ex ) {
			errMsg = ex.toString() + " " + typeName + " class (" + className + ") must have a public, no-arg constructor.";
			System.out.println(errMsg);
			throw new ConfigurationException(errMsg, ex);
		} catch( ClassCastException ex ) {
			errMsg = ex.toString() + " " + typeName + " class (" + className + ") must be a subtype of T in ObjFactory<T>";
			System.out.println(errMsg);
			throw new ConfigurationException(errMsg, ex);
		} catch( Exception ex ) {
			// Because we are using reflection, we want to catch any checked or unchecked Exceptions and
			// re-throw them in a way we can handle them. Because using reflection to construct the object,
			// we can't have the compiler notify us of uncaught exceptions. For example, JavaEncryptor()
			// CTOR can throw [well, now it can] an EncryptionException if something goes wrong. That case
			// is taken care of here.
			//
			// CHECKME: Should we first catch RuntimeExceptions so we just let unchecked Exceptions go through
			//		    unaltered???
			//
			errMsg = ex.toString() + " " + typeName + " class (" + className + ") CTOR threw exception.";
			System.out.println(errMsg);
			throw new ConfigurationException(errMsg, ex);
		}
	}
	
	/**
	 * Public, do nothing CTOR.
	 */
	public ObjFactory()
	{
		; // Empty
	}
}
