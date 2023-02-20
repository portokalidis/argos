import java.io.*;

class LontSigSubmit {
	public static void main(String []arg) {
		BufferedReader in;
		String signature;
		LontClient lont;
		int sensors;

		if (arg.length != 1) {
			System.err.println("Invalid parameters");
			System.err.println("Usage: java LongSigSubmit (SignatureSubmit)");
			System.exit(1);
		}

		try {
			in = new BufferedReader(new FileReader(arg[0]));
			signature = in.readLine();
			lont = new LontClient(signature);
			sensors = lont.startMeasurement();
			System.out.println("Started measurement in "+ sensors +" sensor(s).");
		} catch (FileNotFoundException e) {
			System.err.println("File '" + arg[0] + "' not found");
			System.exit(1);
		} catch (IOException e) {
			System.err.println("Error while reading file '" + arg[0] + "'");
			System.exit(1);
		}
	}
}
