import java.io.*;
import java.util.Date;
import java.util.regex.*;

class ClientProcessor {
	public static final String NET_LOG_NAME = "argos.netlog";
	private String logdir, rhost, rdir;

	public ClientProcessor(String logdir, String rhost, String rdir) {
		this.logdir = logdir;
		this.rhost = rhost;
		this.rdir = rdir;
	}

	public boolean process(String message)
	{
		Pattern p = Pattern.compile("argos.csi.[0-9]+"); 
		Matcher m = p.matcher(message);
		CsiLog log;
		NetLog netLog;
		Signature signature;
		LontClient lont;
		String dir = null;

		if (!m.find()) return false;
		if ((dir = createDir("logs/")) == null) {
			System.err.println("Could not create log directory");
			return true;
		}
		try {
			moveFile(dir + "/" + m.group(), rhost, rdir + "/" + m.group());
			moveFile(dir + "/" + NET_LOG_NAME, rhost, rdir + "/" + NET_LOG_NAME);
		} catch (IOException e) {
			System.err.println("Could not copy Argos log files");
			return true;
		}
		System.out.println("Logs copied");
		log = new CsiLog();
		try {
			log.load(dir + "/" + m.group());
		} catch (FileNotFoundException e) {
			System.err.println("Csi log not found");
			return true;
		} catch (EOFException e) {
			System.err.println("Premature end of csi log");
			return true;
		} catch (IOException e) {
			System.err.println("There was an error loading the csi log");
			return true;
		}

		netLog = new NetLog();
		try {
			netLog.load(dir + "/" + NET_LOG_NAME);
		} catch (FileNotFoundException e) {
			System.err.println("Net log not found");
			return true;
		} catch (IOException e) {
			System.err.println("There was an error loading the net log");
			return true;
		}

		signature = new Signature(log, netLog);
		if (!signature.generate()) {
			System.err.println("There was an error generating a signature");
			return true;
		}

		lont = new LontClient(signature.getString());
		if (lont.startMeasurement() <= 0) {
			System.err.println("There was an error starting a measurement");
			return true;
		}
		return true;
	}

	private static String createDir(String d) {
		boolean b;
		String ts;

		ts = new Date().toString();
		b = new File(d + ts).mkdirs();
		if (b)
			return (d + ts);
		return null;
	}

	protected static void copyFile(String destfn, String srchost, String srcfn) throws IOException {
		if (srchost.compareToIgnoreCase("localhost") != 0 &&
			srchost.compareToIgnoreCase("127.0.0.1") != 0) {
			System.err.println("Remote logs are currently not handled");
			throw new IOException();
		}

		File destfile = new File(destfn);
		File srcfile = new File(srcfn);
		FileInputStream fin = new FileInputStream(srcfile);
		FileOutputStream fout = new FileOutputStream(destfile);
		byte []buf = new byte [1024];
		int i = 0;
		while ((i = fin.read(buf)) != -1) {
			fout.write(buf, 0, i);
		}
		fin.close();
		fout.close();
	}

	protected static void moveFile(String destfn, String srchost, String srcfn) throws IOException {
		copyFile(destfn, srchost, srcfn);

		if (srchost.compareToIgnoreCase("localhost") != 0 &&
			srchost.compareToIgnoreCase("127.0.0.1") != 0) {
			System.err.println("Remote logs are currently not handled");
			System.err.println("Original file will not be deleted");
		}

		File file = new File(srcfn);
		if (!file.delete())
			System.err.println("There was an error removing the original");
	}
}
