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

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A generic object factory to create an object of class T. T must be a concrete
 * class that has a no-argument public constructor or a implementor of the Singleton pattern
 * that has a no-arg static getInstance method. If the class being created has a getInstance
 * method, it will be used as a singleton and newInstance() will never be called on the
 * class no matter how many times it comes through this factory.
 *
 * <p>
 * Typical use is something like:
 * <pre>
 * 		import com.example.interfaces.DrinkingEstablishment;
 * 		import com.example.interfaces.Beer;
 * 		...
 * 		// Typically these would be populated from some Java properties file
 * 		String barName = "com.example.foo.Bar";
 * 		String beerBrand = "com.example.brewery.Guinness";
 * 		...
 * 		DrinkingEstablishment bar = ObjFactory.make(barName, "DrinkingEstablishment");
 * 		Beer beer = ObjFactory.make(beerBrand, "Beer");
 *		bar.drink(beer);	// Drink a Guinness beer at the foo Bar. :)
 *		...
 * </pre>
 * </p><p>
 *  Copyright (c) 2009 - The OWASP Foundation
 *  </p>
 * @author kevin.w.wall@gmail.com
 * @author Chris Schmidt ( chrisisbeef .at. gmail.com )
 */
public class ObjFactory {

    private static final int CACHE_INITIAL_CAPACITY = 32;
	private static final float CACHE_LOAD_FACTOR = 0.75F;
	private static final ConcurrentHashMap<String,Class<?>> CLASSES_CACHE = new ConcurrentHashMap<>(CACHE_INITIAL_CAPACITY, CACHE_LOAD_FACTOR);
	private static final ConcurrentHashMap<String,MethodWrappedInfo> METHODS_CACHE = new ConcurrentHashMap<>(CACHE_INITIAL_CAPACITY, CACHE_LOAD_FACTOR);
    private static boolean cacheEnabled = true;

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
	public static <T> T make(String className, String typeName) throws ConfigurationException {
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

			Class<?> theClass = loadClassByStringName(className);

			try {
				Method singleton = findSingletonCreateMethod(className, theClass);

				obj = singleton.invoke( null );
            } catch (NoSuchMethodException e) {
                // This is a no-error exception, if this is caught we will continue on assuming the implementation was
                // not meant to be used as a singleton.
                obj = theClass.newInstance();
            } catch (SecurityException e) {
                // The class is meant to be singleton, however, the SecurityManager restricts us from calling the
                // getInstance method on the class, thus this is a configuration issue and a ConfigurationException
                // is thrown
                throw new ConfigurationException( "The SecurityManager has restricted the object factory from getting a reference to the singleton implementation " +
                        "of the class [" + className + "]", e );
            }

			return (T)obj;		// Eclipse warning here if @SupressWarnings omitted.

            // Issue 66 - Removed System.out calls as we are throwing an exception in each of these cases
            // anyhow.
		} catch( IllegalArgumentException ex ) {
			errMsg = ex.toString() + " " + typeName + " type name cannot be null or empty.";
			throw new ConfigurationException(errMsg, ex);
		}catch ( ClassNotFoundException ex ) {
			errMsg = ex.toString() + " " + typeName + " class (" + className + ") must be in class path.";
			throw new ConfigurationException(errMsg, ex);
		} catch( InstantiationException ex ) {
			errMsg = ex.toString() + " " + typeName + " class (" + className + ") must be concrete.";
			throw new ConfigurationException(errMsg, ex);
		} catch( IllegalAccessException ex ) {
			errMsg = ex.toString() + " " + typeName + " class (" + className + ") must have a public, no-arg constructor.";
			throw new ConfigurationException(errMsg, ex);
		} catch( ClassCastException ex ) {
			errMsg = ex.toString() + " " + typeName + " class (" + className + ") must be a subtype of T in ObjFactory<T>";
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
			throw new ConfigurationException(errMsg, ex);
		}
		// DISCUSS: Should we also catch ExceptionInInitializerError here? See Google Issue #61 comments.
	}

    /**
     * Control whether cache for classes and method names should be enabled or disabled. Initial state is enabled.
     * Ordinally, you are not expected to want to / have to call this method.  It's major purpose is a "just-in-case"
     * something goes wrong is some weird context where multiple ESAPI jars are loaded into a give application and something
     * goes wrong, etc. A secondary purpose is it allows us to easily disable the cache so we can measure its time savings.
     *
     * @param enable    true - enable cache; false - disable cache
     */
    public static void setCache(boolean enable) {
        cacheEnabled = enable;
    }

	/**
	 * Load the class in cache, or load by the classloader and cache it
	 *
	 * @param className The name of the class to construct. Should be a fully qualified name
	 * @return The target class
	 * @throws ClassNotFoundException Failed to load class by the className
	 */
	private static Class<?> loadClassByStringName(String className) throws ClassNotFoundException {
		Class<?> clazz;
		if (cacheEnabled && CLASSES_CACHE.containsKey(className)) {
			clazz = CLASSES_CACHE.get(className);
		} else {
			clazz = Class.forName(className);
			if ( cacheEnabled ) CLASSES_CACHE.putIfAbsent(className, clazz);
		}
		return clazz;
	}

	/**
	 * Find the method to create a singleton object
	 *
	 * @param className The name of the class to construct. Should be a fully qualified name
	 * @param theClass The class loaded in prior
	 * @return The method to create a singleton object
	 * @throws NoSuchMethodException Failed to find the target method
	 */
    private static Method findSingletonCreateMethod(String className, Class<?> theClass) throws NoSuchMethodException {
        MethodWrappedInfo singleton = loadMethodByStringName(className,theClass);

        // If the implementation class contains a getInstance method that is not static, this is an invalid
        // object configuration and a ConfigurationException will be thrown.
        if (!singleton.isStaticMethod()) {
            throw singleton.getNonStaticEx();
        }
        return singleton.getMethod();
    }

	/**
	 *
	 * @param className The name of the class to construct. Should be a fully qualified name
	 * @param theClass The class loaded in prior
	 * @return Wrapped data, contains the method object and the method is static method or not
	 * @throws NoSuchMethodException Failed to find the target method
	 */
    private static MethodWrappedInfo loadMethodByStringName(String className, Class<?> theClass) throws NoSuchMethodException {
        String methodName = className + "getInstance";
        MethodWrappedInfo methodInfo;
        if (cacheEnabled && METHODS_CACHE.containsKey(methodName)) {
            methodInfo = METHODS_CACHE.get(methodName);
        } else {
            Method method = theClass.getMethod("getInstance");
            boolean staticMethod = Modifier.isStatic(method.getModifiers());
            ConfigurationException nonStaticEx = staticMethod ? null :
                    new ConfigurationException("Class [" + className + "] contains a non-static getInstance method.");
            methodInfo = new MethodWrappedInfo(method, staticMethod, nonStaticEx);
            if ( cacheEnabled ) METHODS_CACHE.putIfAbsent(methodName, methodInfo);
        }
        return methodInfo;
    }

    /**
	 * Not instantiable
	 */
	private ObjFactory() { }

	/**
	 * Wrapped data, contains the method object and the method is static method or not.<br>
	 * The goal to store the boolean value in field staticMethod is reduce the check times: check once, use many times.<br>
     * The goal to store the exception in field nonStaticException is reduce the cost of new Exception(): create once, use many times.
	 */
	private static class MethodWrappedInfo {
		private Method method;
		private boolean staticMethod;
		private ConfigurationException nonStaticEx;

		MethodWrappedInfo(Method method, boolean staticMethod, ConfigurationException nonStaticEx) {
			this.method = method;
			this.staticMethod = staticMethod;
			this.nonStaticEx = nonStaticEx;
		}

		Method getMethod() {
			return method;
		}

		boolean isStaticMethod() {
			return staticMethod;
		}

        ConfigurationException getNonStaticEx() {
            return nonStaticEx;
        }
    }
}
