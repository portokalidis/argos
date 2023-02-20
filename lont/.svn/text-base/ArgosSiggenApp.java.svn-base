import java.io.*;

class ArgosSiggenApp {
	public static void main(String []arg) {
		CsiLog log;
		NetLog nlog;
		Signature sig;

		if (arg.length != 2) {
			System.err.println("Invalid parameters");
			System.err.println("Usage: java ArgosLogApp (CsiLog) (NetLog)");
			System.exit(1);
		}

		log = new CsiLog();
		try {
			log.load(arg[0]);
		} catch (FileNotFoundException e) {
			System.err.println("File '" + arg[0] + "' not found");
			System.exit(1);
		} catch (EOFException e) {
			System.err.println("Premature end of file " + arg[0]);
			System.exit(1);
		} catch (IOException e) {
			System.err.println("Error while reading file '" + arg[0] + "'");
			System.exit(1);
		}

		nlog = new NetLog();
		try {
			nlog.load(arg[1]);
		} catch (FileNotFoundException e) {
			System.err.println("File '" + arg[1] + "' not found");
			System.exit(1);
		} catch (EOFException e) {
			System.err.println("Premature end of file " + arg[1]);
			System.exit(1);
		} catch (IOException e) {
			System.err.println("Error while reading file '" + arg[1] + "'");
			System.exit(1);
		}

		/*
		log.print();
		log.printMemoryBlocks();
		nlog.print();
		*/

		sig = new Signature(log, nlog);
		if (!sig.generate()) {
			System.err.println("There was an error generating a signature");
			System.exit(1);
		}
		//System.out.println("Signature (" + sig.getLength() + "):");
		System.out.println(sig.getString());
	}
}
