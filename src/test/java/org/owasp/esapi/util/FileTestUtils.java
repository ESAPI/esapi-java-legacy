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
	private static final Random rand;

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
	 * {@ Long#toHexString(long)} this always returns 16 digits.
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
			parent = new File(System.getProperty("java.io.tmpdir"));
		name = prefix + randomLongHex() + suffix;
		dir = new File(parent, name);
		if(!dir.mkdir())
			throw new IOException("Unable to create temporary directory " + dir);
		return dir.getCanonicalFile();
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
	 * @return File representing a non-existant file.
	 */
	public static File nonexistantFile() throws IOException
	{
		File file;
		File tmpdir;

		tmpdir = new File(System.getProperty("java.io.tmpdir"));
		if(!tmpdir.exists())
			return tmpdir;

		while((file = new File(tmpdir, randomLongHex())).exists());
		return file;
	}
}
