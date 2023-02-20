import java.util.TimerTask;
import java.util.Timer;
import java.io.IOException;

public class ResetTask extends TimerTask {
	private Timer timer;
	private ArgosClient client;

	public ResetTask(ArgosClient client, int seconds) {
		timer = new Timer(true);
		this.client = client;
		timer.schedule(this, seconds * 1000);
	}

	public void run() {
		try { 
			client.sendReset();
		} catch (IOException e) {
			System.err.println("error resetting argos");
			System.err.println(e);
		}
	}
}

