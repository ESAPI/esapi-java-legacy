package org.owasp.esapi.reference.accesscontrol.policyloader;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.eq;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.Date;
import java.util.Random;

import org.apache.commons.configuration.XMLConfiguration;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;


public class ACRParameterLoaderHelperTest {
   
   
   XMLConfiguration config = Mockito.spy(XMLConfiguration.class);
   
   private String randomTestKey;
   private int randomRuleIndex;
   private int randomParameterIndex;
   
   @Before
   public void buildUniqueKey () {
       // Assembling a unique key each test verifies that the delegate calls are getting the expected values from the test calls.
       randomRuleIndex = Math.abs(new Random().nextInt() % 100);
       randomParameterIndex = Math.abs(new Random().nextInt() % 100);
       randomTestKey = String.format(ACRParameterLoaderHelper.DEFAULT_KEY_FORMAT, randomRuleIndex, randomParameterIndex);
   }
   
   @Test (expected = IllegalArgumentException.class)
   public void testUnsupportedTypeThrowsException() throws Exception {
       ACRParameterLoaderHelper.getParameterValue(config, randomRuleIndex, randomParameterIndex, "Foo_to_the_Bar");
   }
   
   @Test
   public void testStringParam_lowercaseType() throws Exception {
       Mockito.doReturn("unused").when(config).getString(eq(randomTestKey));
       Object response = ACRParameterLoaderHelper.getParameterValue(config, randomRuleIndex, randomParameterIndex, "string".toLowerCase());
       
       // I don't really care what the response is here; 
       // I care that the delegate class was called as expected with the generated string key.
       Mockito.verify(config, Mockito.times(1)).getString(randomTestKey);
       Assert.assertEquals(String.class, response.getClass());
       Assert.assertEquals("unused", response);
   }
   
   @Test
   public void testStringArrayParam_lowercaseType() throws Exception {
       Mockito.doReturn(new String[0]).when(config).getStringArray(eq(randomTestKey));
       // Mockito.when(config.getStringArray(eq(randomTestKey))).thenReturn();
       Object response = ACRParameterLoaderHelper.getParameterValue(config, randomRuleIndex, randomParameterIndex, "stringarray".toLowerCase());
       Mockito.verify(config, Mockito.times(1)).getStringArray(randomTestKey);
       Assert.assertEquals(String[].class, response.getClass());       
   }
   
   @Test
   public void testBooleanParam_lowercaseType() throws Exception {
       Mockito.doReturn(Boolean.TRUE).when(config).getBoolean(eq(randomTestKey));
       // Mockito.when(config.getBoolean(eq(randomTestKey))).thenReturn(Boolean.TRUE);
       Object response = ACRParameterLoaderHelper.getParameterValue(config, randomRuleIndex, randomParameterIndex, "boolean".toLowerCase());
       Mockito.verify(config, Mockito.times(1)).getBoolean(randomTestKey);
       Assert.assertEquals(Boolean.class, response.getClass());
   }
   
   @Test
   public void testByteParam_lowercaseType() throws Exception {
       Mockito.doReturn( (byte)0 ).when(config).getByte( eq(randomTestKey) );
       Object response = ACRParameterLoaderHelper.getParameterValue(config, randomRuleIndex, randomParameterIndex, "byte".toLowerCase());
       Mockito.verify(config, Mockito.times(1)).getByte(randomTestKey);
       Assert.assertEquals(Byte.class, response.getClass());
   }
   
   @Test
   public void testIntParam_lowercaseType() throws Exception {
       Mockito.doReturn(0).when(config).getInt(eq(randomTestKey));
       // Mockito.when(config.getInt(eq(randomTestKey))).thenReturn(0);
       Object response = ACRParameterLoaderHelper.getParameterValue(config, randomRuleIndex, randomParameterIndex, "int".toLowerCase());
       Mockito.verify(config, Mockito.times(1)).getInt(randomTestKey);
       Assert.assertEquals(Integer.class, response.getClass());
   }
   
   @Test
   public void testLongParam_lowercaseType() throws Exception {
       Mockito.doReturn(0L).when(config).getLong(eq(randomTestKey));
       // Mockito.when(config.getLong(eq(randomTestKey))).thenReturn(0L);
       Object response = ACRParameterLoaderHelper.getParameterValue(config, randomRuleIndex, randomParameterIndex, "long".toLowerCase());
       Mockito.verify(config, Mockito.times(1)).getLong(randomTestKey);
       Assert.assertEquals(Long.class, response.getClass());
   }
   
   @Test
   public void testFloatParam_lowercaseType() throws Exception {
       Mockito.doReturn((float) 0).when(config).getFloat(eq(randomTestKey));
       Object response = ACRParameterLoaderHelper.getParameterValue(config, randomRuleIndex, randomParameterIndex, "float".toLowerCase());
       Mockito.verify(config, Mockito.times(1)).getFloat(randomTestKey);
       Assert.assertEquals(Float.class, response.getClass());
   }
   
   @Test
   public void testDoubleParam_lowercaseType() throws Exception {
       Mockito.doReturn(0d).when(config).getDouble(eq(randomTestKey));
       // Mockito.when(config.getDouble(eq(randomTestKey))).thenReturn(0d);
       Object response = ACRParameterLoaderHelper.getParameterValue(config, randomRuleIndex, randomParameterIndex, "double".toLowerCase());
       Mockito.verify(config, Mockito.times(1)).getDouble(randomTestKey);
       Assert.assertEquals(Double.class, response.getClass());
   }
   
   
   @Test
   public void testBigDecimalParam_lowercaseType() throws Exception {
       Mockito.doReturn(new BigDecimal(0)).when(config).getBigDecimal(eq(randomTestKey));
       // Mockito.when(config.getBigDecimal(eq(randomTestKey))).thenReturn();
       Object response = ACRParameterLoaderHelper.getParameterValue(config, randomRuleIndex, randomParameterIndex, "bigdecimal".toLowerCase());
       Mockito.verify(config, Mockito.times(1)).getBigDecimal(randomTestKey);
       Assert.assertEquals(BigDecimal.class, response.getClass());
   }
   
   @Test
   public void testBigIntegerParam_lowercaseType() throws Exception {
       Mockito.doReturn(new BigInteger("0")).when(config).getBigInteger(eq(randomTestKey));
       // Mockito.when(config.getBigInteger(eq(randomTestKey))).thenReturn();
       Object response = ACRParameterLoaderHelper.getParameterValue(config, randomRuleIndex, randomParameterIndex, "biginteger".toLowerCase());
       Mockito.verify(config, Mockito.times(1)).getBigInteger(randomTestKey);
       Assert.assertEquals(BigInteger.class, response.getClass());
   }
   
   @Test
   public void testDateParam_lowercaseType() throws Exception {
       String adate = java.text.DateFormat.getDateInstance().format(new Date());
       Mockito.doReturn(adate).when(config).getString(eq(randomTestKey));
       Object response = ACRParameterLoaderHelper.getParameterValue(config, randomRuleIndex, randomParameterIndex, "date".toLowerCase());
       Mockito.verify(config, Mockito.times(1)).getString(randomTestKey);
       Assert.assertEquals(Date.class, response.getClass());
   }
   
   @Test
   public void testTimeParam_lowercaseType() throws Exception {
       String atime = new java.text.SimpleDateFormat(ACRParameterLoaderHelper.TIME_FORMAT).format(new Date());
       Mockito.doReturn(atime).when(config).getString(eq(randomTestKey));
       Object response = ACRParameterLoaderHelper.getParameterValue(config, randomRuleIndex, randomParameterIndex, "time".toLowerCase());
       Mockito.verify(config, Mockito.times(1)).getString(randomTestKey);
       Assert.assertEquals(Date.class, response.getClass());
   }
   
   
   
   @Test
   public void testStringParam_uppercaseType() throws Exception {
       Mockito.doReturn("unused").when(config).getString(eq(randomTestKey));
       Object response = ACRParameterLoaderHelper.getParameterValue(config, randomRuleIndex, randomParameterIndex, "string".toUpperCase());
       
       // I don't really care what the response is here; 
       // I care that the delegate class was called as expected with the generated string key.
       Mockito.verify(config, Mockito.times(1)).getString(randomTestKey);
       Assert.assertEquals(String.class, response.getClass());
       Assert.assertEquals("unused", response);
   }
   
   @Test
   public void testStringArrayParam_uppercaseType() throws Exception {
       Mockito.doReturn(new String[0]).when(config).getStringArray(eq(randomTestKey));
       // Mockito.when(config.getStringArray(eq(randomTestKey))).thenReturn();
       Object response = ACRParameterLoaderHelper.getParameterValue(config, randomRuleIndex, randomParameterIndex, "stringarray".toUpperCase());
       Mockito.verify(config, Mockito.times(1)).getStringArray(randomTestKey);
       Assert.assertEquals(String[].class, response.getClass());       
   }
   
   @Test
   public void testBooleanParam_uppercaseType() throws Exception {
       Mockito.doReturn(Boolean.TRUE).when(config).getBoolean(eq(randomTestKey));
       // Mockito.when(config.getBoolean(eq(randomTestKey))).thenReturn(Boolean.TRUE);
       Object response = ACRParameterLoaderHelper.getParameterValue(config, randomRuleIndex, randomParameterIndex, "boolean".toUpperCase());
       Mockito.verify(config, Mockito.times(1)).getBoolean(randomTestKey);
       Assert.assertEquals(Boolean.class, response.getClass());
   }
   
   @Test
   public void testByteParam_uppercaseType() throws Exception {
       Mockito.doReturn( (byte)0 ).when(config).getByte( eq(randomTestKey) );
       Object response = ACRParameterLoaderHelper.getParameterValue(config, randomRuleIndex, randomParameterIndex, "byte".toUpperCase());
       Mockito.verify(config, Mockito.times(1)).getByte(randomTestKey);
       Assert.assertEquals(Byte.class, response.getClass());
   }
   
   @Test
   public void testIntParam_uppercaseType() throws Exception {
       Mockito.doReturn(0).when(config).getInt(eq(randomTestKey));
       // Mockito.when(config.getInt(eq(randomTestKey))).thenReturn(0);
       Object response = ACRParameterLoaderHelper.getParameterValue(config, randomRuleIndex, randomParameterIndex, "int".toUpperCase());
       Mockito.verify(config, Mockito.times(1)).getInt(randomTestKey);
       Assert.assertEquals(Integer.class, response.getClass());
   }
   
   @Test
   public void testLongParam_uppercaseType() throws Exception {
       Mockito.doReturn(0L).when(config).getLong(eq(randomTestKey));
       // Mockito.when(config.getLong(eq(randomTestKey))).thenReturn(0L);
       Object response = ACRParameterLoaderHelper.getParameterValue(config, randomRuleIndex, randomParameterIndex, "long".toUpperCase());
       Mockito.verify(config, Mockito.times(1)).getLong(randomTestKey);
       Assert.assertEquals(Long.class, response.getClass());
   }
   
   @Test
   public void testFloatParam_uppercaseType() throws Exception {
       Mockito.doReturn((float) 0).when(config).getFloat(eq(randomTestKey));
       Object response = ACRParameterLoaderHelper.getParameterValue(config, randomRuleIndex, randomParameterIndex, "float".toUpperCase());
       Mockito.verify(config, Mockito.times(1)).getFloat(randomTestKey);
       Assert.assertEquals(Float.class, response.getClass());
   }
   
   @Test
   public void testDoubleParam_uppercaseType() throws Exception {
       Mockito.doReturn(0d).when(config).getDouble(eq(randomTestKey));
       // Mockito.when(config.getDouble(eq(randomTestKey))).thenReturn(0d);
       Object response = ACRParameterLoaderHelper.getParameterValue(config, randomRuleIndex, randomParameterIndex, "double".toUpperCase());
       Mockito.verify(config, Mockito.times(1)).getDouble(randomTestKey);
       Assert.assertEquals(Double.class, response.getClass());
   }
   
   
   @Test
   public void testBigDecimalParam_uppercaseType() throws Exception {
       Mockito.doReturn(new BigDecimal(0)).when(config).getBigDecimal(eq(randomTestKey));
       // Mockito.when(config.getBigDecimal(eq(randomTestKey))).thenReturn();
       Object response = ACRParameterLoaderHelper.getParameterValue(config, randomRuleIndex, randomParameterIndex, "bigdecimal".toUpperCase());
       Mockito.verify(config, Mockito.times(1)).getBigDecimal(randomTestKey);
       Assert.assertEquals(BigDecimal.class, response.getClass());
   }
   
   @Test
   public void testBigIntegerParam_uppercaseType() throws Exception {
       Mockito.doReturn(new BigInteger("0")).when(config).getBigInteger(eq(randomTestKey));
       // Mockito.when(config.getBigInteger(eq(randomTestKey))).thenReturn();
       Object response = ACRParameterLoaderHelper.getParameterValue(config, randomRuleIndex, randomParameterIndex, "biginteger".toUpperCase());
       Mockito.verify(config, Mockito.times(1)).getBigInteger(randomTestKey);
       Assert.assertEquals(BigInteger.class, response.getClass());
   }
   
   @Test
   public void testDateParam_uppercaseType() throws Exception {
       String adate = java.text.DateFormat.getDateInstance().format(new Date());
       Mockito.doReturn(adate).when(config).getString(eq(randomTestKey));
       Object response = ACRParameterLoaderHelper.getParameterValue(config, randomRuleIndex, randomParameterIndex, "date".toUpperCase());
       Mockito.verify(config, Mockito.times(1)).getString(randomTestKey);
       Assert.assertEquals(Date.class, response.getClass());
   }
   
   @Test
   public void testTimeParam_uppercaseType() throws Exception {
       String atime = new java.text.SimpleDateFormat(ACRParameterLoaderHelper.TIME_FORMAT).format(new Date());
       Mockito.doReturn(atime).when(config).getString(eq(randomTestKey));
       Object response = ACRParameterLoaderHelper.getParameterValue(config, randomRuleIndex, randomParameterIndex, "time".toUpperCase());
       Mockito.verify(config, Mockito.times(1)).getString(randomTestKey);
       Assert.assertEquals(Date.class, response.getClass());
   }
    
}
