package org.owasp.esapi.reference.accesscontrol.policyloader;

import org.apache.commons.configuration.XMLConfiguration;

final public class ACRParameterLoaderHelper {
	
	public static Object getParameterValue(XMLConfiguration config, int currentRule, int currentParameter, String parameterType) throws Exception {
		String key = "AccessControlRules.AccessControlRule(" + 
			currentRule + ").Parameters.Parameter(" + currentParameter + ")[@value]";
		Object parameterValue;
		if("String".equalsIgnoreCase(parameterType)) {
			parameterValue = config.getString(key);
		} else if("Boolean".equalsIgnoreCase(parameterType)){ 
			parameterValue = config.getBoolean(key);
		} else if("Byte".equalsIgnoreCase(parameterType)){ 
			parameterValue = config.getByte(key);
		} else if("Int".equalsIgnoreCase(parameterType)){ 
			parameterValue = config.getInt(key);
		} else if("Long".equalsIgnoreCase(parameterType)){ 
			parameterValue = config.getLong(key);
		} else if("Float".equalsIgnoreCase(parameterType)){ 
			parameterValue = config.getFloat(key);
		} else if("Double".equalsIgnoreCase(parameterType)){ 
			parameterValue = config.getDouble(key);
		} else if("BigDecimal".equalsIgnoreCase(parameterType)){ 
			parameterValue = config.getBigDecimal(key);
		} else if("BigInteger".equalsIgnoreCase(parameterType)){ 
			parameterValue = config.getBigInteger(key);
		} else if("Date".equalsIgnoreCase(parameterType)){
			parameterValue = java.text.DateFormat.getDateInstance().parse(config.getString(key));
		} else if("Time".equalsIgnoreCase(parameterType)){
			java.text.SimpleDateFormat sdf = new java.text.SimpleDateFormat("h:mm a");
			parameterValue = sdf.parseObject(config.getString(key)); 
//			parameterValue = java.text.DateFormat.getTimeInstance().parse(config.getString(key));
		}		
		//add timestamp. check for other stuff.
		else {
			throw new IllegalArgumentException("Unable to load the key \"" + key 
					+ "\", because " + "the type \"" + parameterType + 
					"\" was not recognized." );
		}
		return parameterValue;
	}	
}
