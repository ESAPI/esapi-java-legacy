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
package org.owasp.esapi.reference;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.List;
import java.util.Map;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.ExecuteResult;
import org.owasp.esapi.Executor;
import org.owasp.esapi.Logger;
import org.owasp.esapi.codecs.Codec;
import org.owasp.esapi.codecs.UnixCodec;
import org.owasp.esapi.codecs.WindowsCodec;
import org.owasp.esapi.errors.ExecutorException;

/**
 * Reference implementation of the Executor interface. This implementation is very restrictive. Commands must exactly
 * equal the canonical path to an executable on the system. 
 * 
 * <p>Valid characters for parameters are codec dependent, but will usually only include alphanumeric, forward-slash, and dash.</p>
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 * @see org.owasp.esapi.Executor
 */
public class DefaultExecutor implements org.owasp.esapi.Executor {
    private static volatile Executor singletonInstance;

    public static Executor getInstance() {
        if ( singletonInstance == null ) {
            synchronized ( DefaultExecutor.class ) {
                if ( singletonInstance == null ) {
                    singletonInstance = new DefaultExecutor();
                }
            }
        }
        return singletonInstance;
    }

    /** The logger. */
    private final Logger logger = ESAPI.getLogger("Executor");
    private Codec codec = null;
    //private final int MAX_SYSTEM_COMMAND_LENGTH = 2500;
    

    /**
     * Instantiate a new Executor
     */
    private DefaultExecutor() {
		if ( System.getProperty("os.name").indexOf("Windows") != -1 ) {
			logger.warning( Logger.SECURITY_SUCCESS, "Using WindowsCodec for Executor. If this is not running on Windows this could allow injection" );
			codec = new WindowsCodec();
		} else {
			logger.warning( Logger.SECURITY_SUCCESS, "Using UnixCodec for Executor. If this is not running on Unix this could allow injection" );
			codec = new UnixCodec();
		}
    }

    /**
     * {@inheritDoc}
     */
    public ExecuteResult executeSystemCommand(File executable, List params) throws ExecutorException {
    	File workdir = ESAPI.securityConfiguration().getWorkingDirectory();
    	boolean logParams = false;
    	boolean redirectErrorStream = false;
    	return executeSystemCommand( executable, params, workdir, codec, logParams, redirectErrorStream );
    }

    /**
     * {@inheritDoc}
     *
     * The reference implementation sets the work directory, escapes the parameters as per the Codec in use,
     * and then executes the command without using concatenation. The exact, absolute, canonical path of each
     * executable must be listed as an approved executable in the ESAPI properties. The executable must also
     * exist on the disk. All failures will be logged, along with parameters if specified. Set the logParams to false if
     * you are going to invoke this interface with confidential information.
     */
    public ExecuteResult executeSystemCommand(File executable, List params, File workdir, Codec codec, boolean logParams, boolean redirectErrorStream ) throws ExecutorException {
        try {
            // executable must exist
            if (!executable.exists()) {
                throw new ExecutorException("Execution failure", "No such executable: " + executable);
            }
            
            // executable must use canonical path
            if ( !executable.isAbsolute() ) {
                throw new ExecutorException("Execution failure", "Attempt to invoke an executable using a non-absolute path: " + executable);
            }
            
            // executable must use canonical path
            if ( !executable.getPath().equals( executable.getCanonicalPath() ) ) {
            	throw new ExecutorException("Execution failure", "Attempt to invoke an executable using a non-canonical path: " + executable);
        	}
            
            // exact, absolute, canonical path to executable must be listed in ESAPI configuration 
            List approved = ESAPI.securityConfiguration().getAllowedExecutables();
            if (!approved.contains(executable.getPath())) {
                throw new ExecutorException("Execution failure", "Attempt to invoke executable that is not listed as an approved executable in ESAPI configuration: " + executable.getPath() + " not listed in " + approved );
            }

            // escape any special characters in the parameters
            for ( int i = 0; i < params.size(); i++ ) {
            	String param = (String)params.get(i);
            	params.set( i, ESAPI.encoder().encodeForOS(codec, param));
            }
            
            // working directory must exist
            if (!workdir.exists()) {
                throw new ExecutorException("Execution failure", "No such working directory for running executable: " + workdir.getPath());
            }
            
            // set the command into the list and create command array
            params.add(0, executable.getCanonicalPath());

            // Legacy - this is how to implement in Java 1.4
            // String[] command = (String[])params.toArray( new String[0] );
            // Process process = Runtime.getRuntime().exec(command, new String[0], workdir);
            
            // The following is host to implement in Java 1.5+
            ProcessBuilder pb = new ProcessBuilder(params);
            Map env = pb.environment();
            env.clear();  // Security check - clear environment variables!
            pb.directory(workdir);
            pb.redirectErrorStream(redirectErrorStream);

            if ( logParams ) {
            	logger.warning(Logger.SECURITY_SUCCESS, "Initiating executable: " + executable + " " + params + " in " + workdir);
            } else {
            	logger.warning(Logger.SECURITY_SUCCESS, "Initiating executable: " + executable + " [sensitive parameters obscured] in " + workdir);
            }

            final StringBuilder outputBuffer = new StringBuilder();
            final StringBuilder errorsBuffer = new StringBuilder();
            final Process process = pb.start();
            try {
                ReadThread errorReader;
                if (!redirectErrorStream) {
                	errorReader = new ReadThread(process.getErrorStream(), errorsBuffer);
                	errorReader.start();
                } else {
                	errorReader = null;
                }
            	readStream( process.getInputStream(), outputBuffer );
            	if (errorReader != null) {
            		errorReader.join();
            		if (errorReader.exception != null) {
            			throw errorReader.exception;
            		}
            	}
            	process.waitFor();
            } catch (Throwable e) {
            	process.destroy();
            	throw new ExecutorException("Execution failure", "Exception thrown during execution of system command: " + e.getMessage(), e);
            }

            String output = outputBuffer.toString();
            String errors = errorsBuffer.toString();
            int exitValue = process.exitValue();
            if ( errors != null && errors.length() > 0 ) {
            	String logErrors = errors;
            	final int MAX_LEN = 256;
            	if (logErrors.length() > MAX_LEN) {
            		logErrors = logErrors.substring(0, MAX_LEN) + "(truncated at "+MAX_LEN+" characters)";
            	}
            	logger.warning( Logger.SECURITY_SUCCESS, "Error during system command: " + logErrors );
            }
            if ( exitValue != 0 ) {
            	logger.warning( Logger.EVENT_FAILURE, "System command exited with non-zero status: " + exitValue );
            }

            logger.warning(Logger.SECURITY_SUCCESS, "System command complete");
            return new ExecuteResult(exitValue, output, errors);
        } catch (IOException e) {
            throw new ExecutorException("Execution failure", "Exception thrown during execution of system command: " + e.getMessage(), e);
        }
    }

    /**
     * readStream reads lines from an input stream and returns all of them in a single string
     * 
     * @param is
     * 			input stream to read from
     * @throws IOException
     */
    private static void readStream( InputStream is, StringBuilder sb ) throws IOException {
	    InputStreamReader isr = new InputStreamReader(is);
	    BufferedReader br = new BufferedReader(isr);
	    String line;
	    while ((line = br.readLine()) != null) {
	        sb.append(line).append('\n');
	    }
    }
    
    private static class ReadThread extends Thread {
    	volatile IOException exception;
    	private final InputStream stream;
    	private final StringBuilder buffer;

    	ReadThread(InputStream stream, StringBuilder buffer) {
    		this.stream = stream;
    		this.buffer = buffer;
    	}

    	@Override
		public void run() {
    		try {
    			readStream(stream, buffer);
    		} catch (IOException e) {
    			exception = e;
    		}
    	}

    }

}
