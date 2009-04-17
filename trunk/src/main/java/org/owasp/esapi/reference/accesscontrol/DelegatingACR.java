package org.owasp.esapi.reference.accesscontrol;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.StringTokenizer;
import java.util.Vector;

import org.owasp.esapi.AccessControlRule;
import org.owasp.esapi.Validator;



public class DelegatingACR extends BaseACR<DynaBeanACRParameter, Object[]> {
	protected Method delegateMethod;
	protected Object delegateInstance;
	
	@Override
	public void setPolicyParameters(DynaBeanACRParameter policyParameter) {
		String delegateClassName = policyParameter.getString("delegateClass");
		String methodName = policyParameter.getString("delegateMethod");
		String parameterClassNames = policyParameter.getString("parameterClasses");
		
		//Convert the classNames into Classes and get the delegate method.
		Class delegateClass = getClass(delegateClassName, "delegate");
		Class parameterClasses[] = getParameters(parameterClassNames);
		try {
			this.delegateMethod = delegateClass.getMethod(methodName, parameterClasses);
		} catch (SecurityException e) {
			throw new IllegalArgumentException(e.getMessage() + " " +  
					delegateClassName + "." + methodName + "(" + parameterClassNames + 
					") must be public.", e);
		} catch (NoSuchMethodException e) {
			throw new IllegalArgumentException(e.getMessage() + " " +  
					delegateClassName + "." + methodName + "(" + parameterClassNames +
					") does not exist.", e);
		}
	
		//static methods do not need a delegateInstance. Non-static methods do.
		if(!Modifier.isStatic(this.delegateMethod.getModifiers())) {
			try {
				this.delegateInstance = delegateClass.newInstance();
			} catch (InstantiationException ex) {
				throw new IllegalArgumentException(ex.getMessage() + 
						" Delegate class " + delegateClassName + 
						" must be concrete, because method " +
						delegateClassName + "." + methodName + "(" + parameterClassNames +
						") is not static.", ex);
			} catch (IllegalAccessException ex) {
				new IllegalArgumentException(ex.getMessage() + 
						" Delegate class " + delegateClassName + 
						" must must have a zero-argument constructor, because method " +
						delegateClassName + "." + methodName + "(" + parameterClassNames +
						") is not static.", ex);
			}	
		} else {
			this.delegateInstance = null;
		}
	}
	
	protected final Class[] getParameters(String parameterClassNames) {
		if(parameterClassNames == null || "".equals(parameterClassNames.trim())) {
			return new Class[0];
		}
				
		StringTokenizer stok = new StringTokenizer(parameterClassNames, ",", false);
		int numberOfCommas = stok.countTokens();
		Vector<Class> classes = new Vector<Class>(numberOfCommas+1);
		while(stok.hasMoreTokens()) {
			classes.add(getClass(stok.nextToken(), "parameter"));
		}
		return classes.toArray(new Class[classes.size()]);
	}
	
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
	
	public boolean isAuthorized(Object[] runtimeParameters) throws Exception {
		return ((Boolean)delegateMethod.invoke(delegateInstance, runtimeParameters)).booleanValue();
	}
	
}


