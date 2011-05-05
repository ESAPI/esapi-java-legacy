package org.owasp.esapi.reference.accesscontrol;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Iterator;
import java.util.Vector;

import org.apache.commons.collections.iterators.ArrayListIterator;

public class DelegatingACR extends BaseACR<DynaBeanACRParameter, Object[]> {
	protected Method delegateMethod;
	protected Object delegateInstance;
	
	@Override
	public void setPolicyParameters(DynaBeanACRParameter policyParameter) {
		String delegateClassName = policyParameter.getString("delegateClass", "").trim();
		String methodName = policyParameter.getString("delegateMethod", "").trim();
		String[] parameterClassNames = policyParameter.getStringArray("parameterClasses");

		//Convert the classNames into Classes and get the delegate method.
		Class delegateClass = getClass(delegateClassName, "delegate");
		Class parameterClasses[] = getParameters(parameterClassNames);
		try {
			this.delegateMethod = delegateClass.getMethod(methodName, parameterClasses);
		} catch (SecurityException e) {
			throw new IllegalArgumentException(e.getMessage() + 
					" delegateClass.delegateMethod(parameterClasses): \"" +  
					delegateClassName + "." + methodName + "(" + parameterClassNames +
					")\" must be public.", e);
		} catch (NoSuchMethodException e) {
			throw new IllegalArgumentException(e.getMessage() + 
					" delegateClass.delegateMethod(parameterClasses): \"" +  
					delegateClassName + "." + methodName + "(" + parameterClassNames +
					")\" does not exist.", e);
		}
	
		//static methods do not need a delegateInstance. Non-static methods do.
		if(!Modifier.isStatic(this.delegateMethod.getModifiers())) {
			try {
				this.delegateInstance = delegateClass.newInstance();
			} catch (InstantiationException ex) {
				throw new IllegalArgumentException( 
						" Delegate class \"" + delegateClassName + 
						"\" must be concrete, because method " +
						delegateClassName + "." + methodName + "(" + parameterClassNames +
						") is not static.", ex);
			} catch (IllegalAccessException ex) {
				new IllegalArgumentException( 
						" Delegate class \"" + delegateClassName + 
						"\" must must have a zero-argument constructor, because " +
						"method delegateClass.delegateMethod(parameterClasses): \"" +  
						delegateClassName + "." + methodName + "(" + parameterClassNames +
						")\" is not static.", ex);
			}	
		} else {
			this.delegateInstance = null;
		}
	}
	/**
	 * Convert an array of fully qualified class names into an array of Class objects
	 * @param parameterClassNames
	 * @return
	 */
	protected final Class[] getParameters(String[] parameterClassNames) {
		if(parameterClassNames == null) {
			return new Class[0];
		}
		Vector<Class> classes = new Vector<Class>();
		Iterator<String> classNames = new ArrayListIterator(parameterClassNames);
		while(classNames.hasNext()) {
			classes.add(getClass(classNames.next(), "parameter"));
		}
		return classes.toArray(new Class[classes.size()]);
	}
	/**
	 * Convert a single fully qualified class name into a Class object
	 * @param className
	 * @param purpose
	 * @return
	 */
	protected final Class getClass(String className, String purpose) {
		try {
	        Class theClass = Class.forName(className);
	        return theClass;
	    } catch ( ClassNotFoundException ex ) {
			throw new IllegalArgumentException(ex.getMessage() + 
					" " + purpose + " Class " + className + 
					" must be in the classpath", ex);
	    } 
	}
	/**
	 * Delegates to the method specified in setPolicyParameters
	 */
	public boolean isAuthorized(Object[] runtimeParameters) throws Exception {
		return ((Boolean)delegateMethod.invoke(delegateInstance, runtimeParameters)).booleanValue();
	}
}


