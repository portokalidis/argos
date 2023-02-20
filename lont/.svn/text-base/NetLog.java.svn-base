import java.io.*;
import java.util.Vector;
import java.util.Enumeration;

class NetLog {
	protected Vector<EthernetFrame> ethFrames;
	protected long size;

	public NetLog() {
		ethFrames = new Vector<EthernetFrame>();
		size = 0;
	}

	public void load(String name) throws FileNotFoundException, EOFException, IOException {
		EthernetFrame ef;
		File logfile = new File(name);
		CustomDataInput in = new CustomDataInput(new DataInputStream(new BufferedInputStream(new FileInputStream(logfile))));
		int el;

		while (true) {
			ef = new EthernetFrame(size + 1); // XXX Offset starts from 1 not zero
			if ((el = ef.readEthernetFrame(in)) <= 0) {
				break;
			}
			ethFrames.add(ef);
			size = size + el;
		}
	}

	public EthernetFrame findEthernetFrame(long idx) {
		EthernetFrame ef;
		for (Enumeration e = ethFrames.elements(); e.hasMoreElements(); ) {
			ef = (EthernetFrame)e.nextElement();
			if (ef.containsIndex(idx)) {
				return ef;
			}
		}
		return null;
	}

	public void print() {
		int i = 0;
		System.out.println("Log size: " + size);
		
		System.out.println("Pkt No\tBase\tSize");
		EthernetFrame ef;
		for (Enumeration e = ethFrames.elements(); e.hasMoreElements(); ) {
			ef = (EthernetFrame)e.nextElement();
			System.out.print(i++ + "\t");
			ef.print();
		}
	}
}
