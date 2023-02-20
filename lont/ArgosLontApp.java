import java.io.*;

class ArgosLontApp {
	static final int DefaultArgosPort = 1374;
	static final int DefaultReconnectPeriod = 10000;
	
	public static void main(String arg[]) {
		int port = DefaultArgosPort;
		ArgosClient client;
		String clientWorkingDir, clientInput;
		ClientProcessor processor = null;
		ResetTask task = null;

		if (arg.length == 2)
			port = Integer.getInteger(arg[1]);
		else if (arg.length != 1) {
			System.err.println("Invalid parameter specification.");
			System.err.println("Usage: java ArgosLontApp hostname [port]");
			System.exit(1);
		}

		while (true) {
			client = new ArgosClient(arg[0], port);
			try {
				client.connect();
				System.out.println("Connected");
				clientWorkingDir = client.readWorkingDir();
				System.out.println("Working directory:" + clientWorkingDir);
				processor = new ClientProcessor("logs", arg[0], clientWorkingDir);
				System.out.flush();
				while ((clientInput = client.readLine()) != null) {
					if (processor.process(clientInput)) {
						if (task != null)
							task.cancel();
						task = new ResetTask(client, 30);
					}
				}
			} catch (IOException e) {
				System.out.println("Disconnected");
			}
			client = null;
			System.out.println("Reconnection attempt in " + DefaultReconnectPeriod / 1000 + " seconds");
			try {
				Thread.sleep(DefaultReconnectPeriod);
			} catch (InterruptedException e) {
				System.err.println(e);
			}
		}
	}
}
