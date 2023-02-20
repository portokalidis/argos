import java.net.*;
import java.io.*;

class ArgosClient {
	private String hostname;
	private int port;
	private Socket sock;
	private PrintWriter out;
	private BufferedReader in;
	
	public ArgosClient(String hostname, int port) {
		this.hostname = hostname;
		this.port = port;
		sock = null; out = null;
	}

	public void connect() throws IOException {
		try {
			sock = new Socket(hostname, port);
			out = new PrintWriter(sock.getOutputStream(), true);
			in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
		} catch (UnknownHostException e) {
			System.err.println("Error connecting to " + hostname);
			System.err.println("Unknown host");
			throw new IOException();
		} catch (IOException e) {
			System.err.println("Error connecting to " + hostname);
			//System.err.println(e);
			throw e;
		}
	}

	public void disconnect() {
		out.close();
		try {
			in.close();
			sock.close();
		} catch (IOException e) {
			System.err.println("Error while closing connection: " + e);
		}
	}

	public String readWorkingDir() throws IOException {
		String wd;
		if ((wd = in.readLine()) == null) throw new IOException();
		return wd;
	}

	public void sendReset() throws IOException {
		out.println("reset");
	}

	public void sendShutdown() throws IOException {
		out.println("shutdown");
	}

	public String readLine() throws IOException {
		return in.readLine();
	}
}
