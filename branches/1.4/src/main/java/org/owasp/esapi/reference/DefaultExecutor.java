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

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.ExecuteResult;
import org.owasp.esapi.Logger;
import org.owasp.esapi.codecs.Codec;
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

    /** The logger. */
    private final Logger logger = ESAPI.getLogger("Executor");
    
    //private final int MAX_SYSTEM_COMMAND_LENGTH = 2500;
    

    /**
     * Instantiate a new Executor
     */
    public DefaultExecutor() {
    }

    /**
     * {@inheritDoc}
     * 
     * <p>The reference implementation calls <tt>executeProgram( ... ).getOutput()</tt>.</p>
     */
    public String executeSystemCommand(File executable, List params, File workdir, Codec codec) throws ExecutorException {
    	return executeProgram(executable, params, workdir, codec).getOutput();
    }

    /**
     * {@inheritDoc}
     * 
     * <p>The reference implementation sets the work directory, escapes the parameters as per the Codec in use,
     * and then executes the command without using concatenation.</p> 
     * 
     * <p>If there are failures, it will be logged. 
     * 
     * <p><b>Privacy Note</b>: Be careful if you pass PII to the executor, as the reference implementation logs
     * the parameters. You MUST change this behavior if you are passing credit card numbers, TIN/SSN, or 
     * health information through this reference implementation, such as to a credit card or HL7 gateway.</p> 
     */
    public ExecuteResult executeProgram(File executable, List params, File workdir, Codec codec) throws ExecutorException {
        try {
            logger.warning(Logger.SECURITY, true, "Initiating executable: " + executable + " " + params + " in " + workdir);
 
            // command must exactly match the canonical path and must actually exist on the file system
            // using equalsIgnoreCase for Windows, although this isn't quite as strong as it should be
            if (!executable.getCanonicalPath().equalsIgnoreCase(executable.getPath())) {
                throw new ExecutorException("Execution failure", "Invalid path to executable file: " + executable);
            }
            if (!executable.exists()) {
                throw new ExecutorException("Execution failure", "No such executable: " + executable);
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
            
            params.add(0, executable.getCanonicalPath());
            String[] command = (String[])params.toArray( new String[0] );
            
            // Future - this is how to implement this in Java 1.5+
            // ProcessBuilder pb = new ProcessBuilder(params);
            // Map env = pb.environment();
            // Security check - clear environment variables!
            // env.clear();
            // pb.directory(workdir);
            // pb.redirectErrorStream(true);
            // Process process = pb.start();

            final StringBuffer outputBuffer = new StringBuffer();
            final StringBuffer errorsBuffer = new StringBuffer();

            final Process process = Runtime.getRuntime().exec(command, new String[0], workdir);
            try {
                ReadThread errorReader = new ReadThread(process.getErrorStream(), errorsBuffer);
                errorReader.start();
                readStream( process.getInputStream(), outputBuffer );
                errorReader.join();
                if (errorReader.exception != null) {
                    throw errorReader.exception;
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
                logger.warning( Logger.SECURITY, false, "Error during system command: " + errors );
            }
            if ( exitValue != 0 ) {
                logger.warning( Logger.SECURITY, false, "System command exited with non-zero status: " + exitValue );
            }
            logger.warning(Logger.SECURITY, true, "System command complete: " + params);
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
     * @return
     * 			a string containing as many lines as the input stream contains, with newlines between lines
     * @throws IOException
     */
    private static void readStream( InputStream is, StringBuffer sb ) throws IOException {
	    InputStreamReader isr = new InputStreamReader(is);
	    BufferedReader br = new BufferedReader(isr);
	    String line;
	    while ((line = br.readLine()) != null) {
	        sb.append(line).append("\n");
	    }
    }

    private static class ReadThread extends Thread {
        volatile IOException exception;
        private final InputStream stream;
        private final StringBuffer buffer;

        ReadThread(InputStream stream, StringBuffer buffer) {
            this.stream = stream;
            this.buffer = buffer;
        }

        public void run() {
            try {
                readStream(stream, buffer);
            } catch (IOException e) {
                exception = e;
            }
        }

    }

}
