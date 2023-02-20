import lobster.lont.*;
import lobster.clientdata.jaws.*;
import java.rmi.RemoteException;
import java.util.Calendar;

public class LontClient {
	protected Webservice service;
	protected LoNTService port;
	protected String sessionId;
	protected Measurement measurement;
	protected MeasurementSpec measurementSpec;
	protected String filterString;

	public static final String MEASUREMENT_NAME = 
		"Argos-LoNT ";
	public static final String RULE_NAME = "Argos Signature Filter";

	public LontClient(String filter) {
		service = new WebserviceLocator();
		filterString = filter;
	}

	protected int applyToSensors(ApplyFunction function) throws RemoteException {
		int i, ruleId = 1;
		Sensor []sensors = port.getSensors(sessionId);
		String sensorUsages[] = new String[sensors.length];
		FilterRule rule = new FilterRule();
		Calendar cal;

		for (i = 0; i < sensors.length; i++) {
			sensorUsages[i] = sensors[i].getSensorAddress();
			System.out.println("Sensor: " + sensorUsages[i]);
		}
		measurementSpec.setSensorUsageArray(sensorUsages);

		rule.setFilterRuleId(ruleId);
		rule.setApplyFunction(function);
		rule.setName(RULE_NAME);
		rule.setParameter1(filterString);
		rule.setParameter2("0");
		rule.setParameter3("0");

		measurementSpec.setFilterRuleTreeRoot(rule);
		cal = Calendar.getInstance();
		measurement.setStartTime(cal);
		cal.add(Calendar.YEAR, 1);
		measurement.setStopTime(cal);
		port.updateMeasurementSpec(sessionId, measurementSpec);

		return i;
	}

	protected int applyFunction() throws Exception {
		ApplyFunction []applyFunctions = port.getApplyFunctions(sessionId);
		ApplyFunction strSearch = null;
		int i;

		for (i = 0; i < applyFunctions.length; i++)
			if (applyFunctions[i].getName().equals("STR_SEARCH")) {
				strSearch = applyFunctions[i];
				break;
			}
		if (strSearch == null)
			throw new Exception("STR_SEARCH function not found\n");
		
		return applyToSensors(strSearch);
	}

	public int startMeasurement() {
		long measurementId;
		String name;

		try {
			port = service.getLoNTServicePort();
			sessionId = port.startSession("root", "lobster");
			if (sessionId == null) {
				System.err.println("Invalid username/password");
				return 0;
			}
			measurement = port.createMeasurement(sessionId);
			measurementId = measurement.getMeasurementId();
			name = MEASUREMENT_NAME + measurementId;
			measurement.setName(name);
			measurementSpec = port.getMeasurementSpec(sessionId, measurementId);

			return applyFunction();
		} catch (RemoteException e) {
			System.err.println("Error connecting to service");
			System.err.println(e);
		} catch (Exception e) {
			System.err.println(e);
		}
		return 0;
	}
}
