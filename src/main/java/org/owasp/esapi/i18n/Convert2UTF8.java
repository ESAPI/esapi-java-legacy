package org.owasp.esapi.i18n;

/**
 * @author Pawan Singh
 */

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FilenameFilter;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;

import org.apache.tools.ant.BuildException;
import org.apache.tools.ant.Task;

public class Convert2UTF8 extends Task {
	private String srcDir;
	private String srcExtension = ".properties";
	private String srcEncoding;

	private String destDir;
	private String destExtension = ".utf8";

	public void execute() throws BuildException {
		System.out.println("Begin Convert2UTF8. srcDir=[" + srcDir
				+ "] destDir=[" + destDir + "]");
		if (srcDir == null) {
			throw new BuildException("srcDir must be defined.");
		}
		if (destDir == null) {
			throw new BuildException("destDir must be defined.");
		}
		if (!srcExtension.startsWith(".")) {
			throw new BuildException(
					"srcExtension must start with period ('.').");
		}
		if (!destExtension.startsWith(".")) {
			throw new BuildException(
					"destExtension must start with period ('.').");
		}

		File fileSrcDir = new File(srcDir);
		String[] fileNameList = fileSrcDir.list(new FilenameFilter() {
			public boolean accept(File d, String name) {
				return name.endsWith(srcExtension);
			}
		});
		for (int i = 0; i < fileNameList.length; i++) {
			String srcFileName = fileNameList[i];
			String destFileName = srcFileName.replaceFirst(srcExtension,
					destExtension);
			System.out.println("Index[" + i + "]: srcFileName=" + srcFileName
					+ " destFileName=" + destFileName);
			if (srcEncoding != null && srcEncoding.length() != 0) {
				encodeFile(srcDir + "/" + srcFileName, srcEncoding, destDir
						+ "/" + destFileName, "UTF8");
			} else if (srcFileName.indexOf("_ja") > 0) {
				encodeFile(srcDir + "/" + srcFileName, "SHIFT_JIS", destDir
						+ "/" + destFileName, "UTF8");
			} else if (srcFileName.indexOf("_ko") > 0) {
				encodeFile(srcDir + "/" + srcFileName, "CP949", destDir + "/"
						+ destFileName, "UTF8");
			} else if (srcFileName.indexOf("_zhs") > 0) {
				encodeFile(srcDir + "/" + srcFileName, "MS936", destDir + "/"
						+ destFileName, "UTF8");
			} else if (srcFileName.indexOf("_zht") > 0) {
				encodeFile(srcDir + "/" + srcFileName, "MS950", destDir + "/"
						+ destFileName, "UTF8");
			} else {
				encodeFile(srcDir + "/" + srcFileName, "ISO-8859-1", destDir
						+ "/" + destFileName, "UTF8");
			}
		}

		System.out.println("End Convert2UTF8.");

	}

	private static void encodeFile(String srcFileName, String srcFileEncoding,
			String outFileName, String outFileEncoding) {
		System.out.println("encodeFile: srcFileName=" + srcFileName
				+ " srcFileEncoding=" + srcFileEncoding);
		System.out.println("encodeFile: outFileName=" + outFileName
				+ " srcFileEncoding=" + outFileEncoding);
		try {
			BufferedReader br = new BufferedReader(new InputStreamReader(
					new FileInputStream(srcFileName), srcFileEncoding));
			BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(
					new FileOutputStream(outFileName), outFileEncoding));
			String str = "";
			while ((str = br.readLine()) != null)
				bw.write(str + "\n");
			br.close();
			bw.close();
		} catch (Exception e) {
			System.out.println("Error:" + e.getMessage());
			System.out.println("srcFileName:[" + srcFileName
					+ "] outFileName:[" + outFileName + "].");
		}
	}

	public void setDestDir(String destDir) {
		this.destDir = destDir;
	}

	public void setSrcDir(String srcDir) {
		this.srcDir = srcDir;
	}

	public void setSrcEncoding(String srcEncoding) {
		this.srcEncoding = srcEncoding;
	}

	public void setSrcExtension(String srcExtension) {
		this.srcExtension = srcExtension;
	}

	public void setDestExtension(String destExtension) {
		this.destExtension = destExtension;
	}
}
