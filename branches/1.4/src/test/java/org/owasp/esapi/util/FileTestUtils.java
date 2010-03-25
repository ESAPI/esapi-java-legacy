package org.owasp.esapi.util;

import java.io.File;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Random;

/**
 * Utilities to help with tests that involve files or directories.
 */
public class FileTestUtils
{
	private static final Class CLASS = FileTestUtils.class;
	private static final String CLASS_NAME = CLASS.getName();
	private static final String DEFAULT_PREFIX = CLASS_NAME + '.';
	private static final String DEFAULT_SUFFIX = ".tmp";
	private static final boolean IS_WINDOWS = (System.getProperty("os.name").indexOf("Windows") >= 0);
	private static final Random rand;
	private static File javaHome;
	private static File javaBin;
	private static File javaExe;
	private static File userDir;
	private static File javaIoTmpDir;

	/*
		Rational for switching from SecureRandom to Random:
		
		This is used for generating filenames for temporary
		directories. Origionally this was using SecureRandom for
		this to make /tmp races harder. This is not necessary as
		mkdir always returns false if if the directory already
		exists.
		
		Additionally, SecureRandom for some reason on linux
		is appears to be reading from /dev/random instead of
		/dev/urandom. As such, the many calls for temporary
		directories in the unit tests quickly depleates the
		entropy pool causing unit test runs to block until more
		entropy is collected (this is why moving the mouse speeds
		up unit tests).
	*/
	static
	{
		SecureRandom secRand = new SecureRandom();
		rand = new Random(secRand.nextLong());
	}

	/** Private constructor as all methods are static. */
	private FileTestUtils()
	{
	}

	/**
	 * Convert a long to it's hex representation. Unlike
	 * {@link Long#toHexString(long)} this always returns 16 digits.
	 * @param l The long to convert.
	 * @return l in hex.
	 */
	private static String toHexString(long l)
	{
		String initial;
		StringBuffer sb;

		initial = Long.toHexString(l);
		if(initial.length() == 16)
			return initial;
		sb = new StringBuffer(16);
		sb.append(initial);
		while(sb.length()<16)
			sb.insert(0,'0');
		return sb.toString();
	}

	/**
	 * Get the next random long from the static random.
	 * @return random long value.
	 */
	private static synchronized long getRandomLong()
	{
		return rand.nextLong();
	}

	/**
	 * Generate a hex string based on a random long.
	 * @return hex representation of a random long value.
	 */
	private static String randomLongHex()
	{
		return toHexString(getRandomLong());
	}

	/**
	 * Create a temporary directory.
	 * @param parent The parent directory for the temporary
	 *	directory. If this is null, the system property
	 * 	"java.io.tmpdir" is used.
	 * @param prefix The prefix for the directory's name. If this
	 * 	is null, the full class name of this class is used.
	 * @param suffix The suffix for the directory's name. If this
	 * 	is null, ".tmp" is used.
	 * @return The newly created temporary directory.
	 * @throws IOException if directory creation fails
	 * @throws SecurityException if {@link File#mkdir()} throws one.
	 */
	public static File createTmpDirectory(File parent, String prefix, String suffix) throws IOException
	{
		String name;
		File dir;

		if(prefix == null)
			prefix = DEFAULT_PREFIX;
		else if(!prefix.endsWith("."))
			prefix += '.';
		if(suffix == null)
			suffix = DEFAULT_SUFFIX;
		else if(!suffix.startsWith("."))
			suffix = "." + suffix;
		if(parent == null)
			parent = getJavaIoTmpDir();
		name = prefix + randomLongHex() + suffix;
		dir = new File(parent, name);
		if(!dir.mkdir())
			throw new IOException("Unable to create temporary directory " + dir);
		dir = dir.getCanonicalFile();
		return dir;
	}

	/**
	 * Create a temporary directory. This calls
	 * {@link #createTmpDirectory(File, String, String)} with null
	 * for parent and suffix.
	 * @param prefix The prefix for the directory's name. If this
	 * 	is null, the full class name of this class is used.
	 * @return The newly created temporary directory.
	 * @throws IOException if directory creation fails
	 * @throws SecurityException if {@link File#mkdir()} throws one.
	 */
	public static File createTmpDirectory(String prefix) throws IOException
	{
		return createTmpDirectory(null, prefix, null);
	}

	/**
	 * Create a temporary directory. This calls
	 * {@link #createTmpDirectory(File, String, String)} with null
	 * for parent and suffix.
	 * @param cls The class who's name is used for the file prefix.
	 * @return The newly created temporary directory.
	 * @throws IOException if directory creation fails
	 * @throws SecurityException if {@link File#mkdir()} throws one.
	 * @throws NullPointerException if cls is null.
	 */
	public static File createTmpDirectory(Class cls) throws IOException
	{
		return createTmpDirectory(null, cls.getName(), null);
	}

	/**
	 * Create a temporary directory. This calls
	 * {@link #createTmpDirectory(File, String, String)} with null
	 * for all arguments.
	 * @return The newly created temporary directory.
	 * @throws IOException if directory creation fails
	 * @throws SecurityException if {@link File#mkdir()} throws one.
	 */
	public static File createTmpDirectory() throws IOException
	{
	 	return createTmpDirectory(null,null,null);
	}

	/**
	 * Create a temporary file.
	 * @param parent The directory to create the file in. If this is
	 *	not null,
	 * 	{@link File#createTempFile(String,String,File)} is used
	 * 	to create the file. Otherwise
	 * 	{@link File#createTempFile(String,String)} is.
	 * @param prefix The file name's prefix. If this is null, this
	 *	class name is used. A period is appended to the prefix
	 * 	if one is not present.
	 * @param suffix The suffix for the file. If this is null,
	 *	".tmp" is used. If the first character is not a period,
	 * 	one is prepended.
	 * @return The {@link File#getCanonicalFile() canonical} File for the temporary file created.
	 * @throws IOException if file creation or canonicalization does.
	 * @throws SecurityException if file creation or canonicalization does.
	 */
	public static File createTmpFile(File parent, String prefix, String suffix) throws IOException
	{
		File file;

		if(prefix == null)
			prefix = DEFAULT_PREFIX;
		else if(!prefix.endsWith("."))
			prefix += '.';
		if(suffix == null)
			suffix = DEFAULT_SUFFIX;
		else if(!suffix.startsWith("."))
			suffix = "." + suffix;
		if(parent == null)
			file = File.createTempFile(prefix, suffix);
		else
			file = File.createTempFile(prefix, suffix, parent);
		file = file.getCanonicalFile();
		return file;
	}

	/**
	 * Create a tmporary file. This simply delegates
	 * to {@link #createTmpFile(File,String,String)
	 * createTmpFile(null,prefix.null)}.
	 * @param prefix The prefix to pass to createTmpFile(File,
	 * 	String, String)
	 */
	public static File createTmpFile(String prefix) throws IOException
	{
		return createTmpFile(null,prefix,null);
	}

	/**
	 * Create a tmporary file. This simply delegates
	 * to {@link #createTmpFile(File,String,String)
	 * createTmpFile(null,cls.getName().null)}.
	 * @param cls Class who's name will be used for the prefix.
	 * @throws NullPointerException if cls is null.
	 */
	public static File createTmpFile(Class cls) throws IOException
	{
		return createTmpFile(null,cls.getName(),null);
	}

	/**
	 * Create a tmporary file. This simply delegates
	 * to {@link #createTmpFile(File,String,String)
	 * createTmpFile(null,null.null)}.
	 */
	public static File createTmpFile() throws IOException
	{
		return createTmpFile(null,null,null);
	}

	/**
	 * Checks that child is a directory and really a child of
	 * parent. This verifies that the {@link File#getCanonicalFile()
	 * canonical} child is actually a child of parent. This should
	 * fail if the child is a symbolic link to another directory and
	 * therefore should not be traversed in a recursive traversal of
	 * a directory.
	 * @param parent The supposed parent of the child
	 * @param child The child to check
	 * @return true if child is a directory and a direct decendant
	 * 	of parent.
	 * @throws IOException if {@link File#getCanonicalFile()} does
	 * @throws NullPointerException if either parent or child
	 * 	are null.
	 */
	public static boolean isChildSubDirectory(File parent, File child) throws IOException
	{
		File childsParent;

		if(child==null)
			throw new NullPointerException("child argument is null");
		if(!child.isDirectory())
			return false;
		if(parent==null)
			throw new NullPointerException("parent argument is null");
		parent = parent.getCanonicalFile();
		child = child.getCanonicalFile();
		childsParent = child.getParentFile();
		if(childsParent == null)
			return false;	// sym link to /?
		childsParent = childsParent.getCanonicalFile();	// just in case...
		if(!parent.equals(childsParent))
			return false;
		return true;
	}

	/**
	 * Delete a file. Unlinke {@link File#delete()}, this throws an
	 * exception if deletion fails.
	 * @param file The file to delete
	 * @throws IOException if file is not null, exists but delete
	 * 	fails.
	 */
	public static void delete(File file) throws IOException
	{
		if(file==null || !file.exists())
			return;
		if(!file.delete())
			throw new IOException("Unable to delete file " + file.getAbsolutePath());
	}

	/**
	 * Recursively delete a file. If file is a directory,
	 * subdirectories and files are also deleted. Care is taken to
	 * not traverse symbolic links in this process. A null file or
	 * a file that does not exist is considered to already been
	 * deleted.
	 * @param file The file or directory to be deleted
	 * @throws IOException if the file, or a descendant, cannot
	 * 	be deleted.
	 * @throws SecurityException if {@link File#delete()} does.
	 */
	public static void deleteRecursively(File file) throws IOException
	{
		File[] children;
		File child;

		if(file == null || !file.exists())
			return;	// already deleted?
		if(file.isDirectory())
		{
			children = file.listFiles();
			for(int i=0;i<children.length;i++)
			{
				child = children[i];
				if(isChildSubDirectory(file,child))
					deleteRecursively(child);
				else
					delete(child);
			}
		}

		// finally
		delete(file);
	}

	/**
	 * Find a file that does not currently exist.
	 * @param dir The directory the file should be in. If
	 *	this is null, {@link System#getProperty(String)
	 *	System.getProperty("java.io.tmpdir")} is used.
	 * @return File representing a non-existant file.
	 */
	public static File getNonexistantFile(File dir) throws IOException
	{
		File file;

		if(dir == null)
			dir = getJavaIoTmpDir();
		else if(!dir.isDirectory())
			throw new IllegalArgumentException("File " + dir + " is not a directory.");
		while((file = new File(dir, randomLongHex())).exists());
		return file;
	}

	/**
	 * Find a file that does not currently exist.
	 * @return File representing a non-existant file.
	 */
	public static File getNonexistantFile() throws IOException
	{
		return getNonexistantFile(null);
	}

	/**
	 * Get a valid regular file.
	 * @return a {@link File#getCanonicalFile() canonicalized}
	 * 	valid regular file
	 */
	public static File getValidFile() throws IOException
	{
		return getJavaExe();
	}

	/**
	 * Get a valid directory.
	 * @return a {@link File#getCanonicalFile() canonicalized}
	 * 	valid directory.
	 */
	public static File getValidDirectory() throws IOException
	{
		return getJavaHome();
	}

	/**
	 * Get a file based on a file name from a system property.
	 * @param propName the name of the system property.
	 * @param isDirectory If true, the file will be verified to be
	 * 	a directory. Otherwise the file will be validated
	 * 	to exist.
	 * @return a validated and {@link File#getCanonicalFile()
	 * 	canonicalized} File for the given property's value.
	 * @throws IllegalArgumentException if propName is not a current
	 * 	system property.
	 * @throws IOException if validation or canonicalization fails.
	 */
	private static File getSystemPropertyFile(String propName, boolean isDirectory) throws IOException
	{
		File file;
		String propValue;

		if((propValue = System.getProperty(propName))==null)
			throw new IllegalArgumentException("System property " + propName + " does not exist.");
		file = new File(propValue).getCanonicalFile();
		if(!file.exists())
			throw new IOException("System property " + propName + " is " + propValue + " which is not a valid file.");
		if(isDirectory)
		{
			if(!file.isDirectory())
				throw new IOException("System property " + propName + " is " + propValue + " is not a directory.");
		}
		else
		{
			if(file.isDirectory())
				throw new IOException("System property " + propName + " is " + propValue + " is a directory.");
		}

		return file;
	}

	/**
	 * Get a file based on a file name from a system property.
	 * @param propName the name of the system property.
	 * @return a validated and {@link File#getCanonicalFile()
	 * 	canonicalized} File for the given property's value.
	 * @throws IllegalArgumentException if propName is not a current
	 * 	system property.
	 * @throws IOException if validation or canonicalization fails.
	 */
	private static File getSystemPropertyFile(String propName) throws IOException
	{
		return getSystemPropertyFile(propName, false);
	}

	/**
	 * Get a directory based on a directory name from a system
	 * property.
	 * @param propName the name of the system property.
	 * @return a validated and {@link File#getCanonicalFile()
	 * 	canonicalized} File for the given property's value.
	 * @throws IllegalArgumentException if propName is not a current
	 * 	system property.
	 * @throws IOException if validation or canonicalization fails.
	 */
	private static File getSystemPropertyDirectory(String propName) throws IOException
	{
		return getSystemPropertyFile(propName, true);
	}

	/**
	 * Get a {@link File} for the system property "java.home".
	 * @return a validated and {@link File#getCanonicalFile()
	 * 	canonicalized} File for the "java.home" system property.
	 * @throws IOException if validation or canonicalization fails.
	 */
	public static synchronized File getJavaHome() throws IOException
	{
		if(javaHome == null)
			javaHome = getSystemPropertyDirectory("java.home");
		return javaHome;
	}

	/**
	 * Get a {@link File} for the system property "user.dir".
	 * @return a validated and {@link File#getCanonicalFile()
	 * 	canonicalized} File for the "user.dir" system property.
	 * @throws IOException if validation or canonicalization fails.
	 */
	public static synchronized File getUserDir() throws IOException
	{
		if(userDir == null)
			userDir = getSystemPropertyDirectory("user.dir");
		return userDir;
	}

	/**
	 * Get a {@link File} for the system property "user.home".
	 * @return a validated and {@link File#getCanonicalFile()
	 * 	canonicalized} File for the "user.home" system property.
	 * @throws IOException if validation or canonicalization fails.
	 */
	public static synchronized File getUserHome() throws IOException
	{
		if(userDir == null)
			userDir = getSystemPropertyDirectory("user.home");
		return userDir;
	}

	/**
	 * Get a {@link File} for the system property "java.io.tmpdir".
	 * @return a validated and {@link File#getCanonicalFile()
	 *	canonicalized} File for the "java.io.tmpdir" system
	 * 	property.
	 * @throws IOException if validation or canonicalization fails.
	 */
	public static synchronized File getJavaIoTmpDir() throws IOException
	{
		if(javaIoTmpDir == null)
			javaIoTmpDir = getSystemPropertyDirectory("java.io.tmpdir");
		return javaIoTmpDir;
	}

	/**
	 * Get a {@link File} for the directory containing the java
	 * executable.
	 * @return a validated and {@link File#getCanonicalFile()
	 *	canonicalized} File for the directory containg the
	 * 	java executable.
	 * @throws IOException if validation or canonicalization fails.
	 */
	public static synchronized File getJavaBin() throws IOException
	{
		File file;

		if(javaBin == null)
		{
			file = new File(getJavaHome(),"bin").getCanonicalFile();
			if(!file.isDirectory())
				throw new IOException("java.home is " + System.getProperty("java.home") + " but does not contain a subdirectory bin.");
			javaBin = file;
		}
		return javaBin;
	}

	/**
	 * Get a {@link File} for the the java executable.
	 * @return a validated and {@link File#getCanonicalFile()
	 *	canonicalized} File for the java executable.
	 * @throws IOException if validation or canonicalization fails.
	 */
	public static synchronized File getJavaExe() throws IOException
	{
		File file;

		if(javaExe == null)
		{
			file = new File(getJavaBin(),"java" + (IS_WINDOWS ? ".exe" : "")).getCanonicalFile();
			if(!file.exists())
				throw new IOException("java.home is " + System.getProperty("java.home") + " but does not contain a java executable in the bin subdirectory");
			if(file.isDirectory())
				throw new IOException("java.home is " + System.getProperty("java.home") + " but the expected java executable in the bin subdirectory is a directory");
			javaExe = file;
		}
		return javaExe;
	}
}
