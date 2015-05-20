package snmp;


import java.io.IOException;

import org.dsa.iot.dslink.node.Node;
import org.dsa.iot.dslink.node.Permission;
import org.dsa.iot.dslink.node.actions.Action;
import org.dsa.iot.dslink.node.actions.ActionResult;
import org.dsa.iot.dslink.node.actions.Parameter;
import org.dsa.iot.dslink.node.value.ValueType;
import org.snmp4j.MessageDispatcher;
import org.snmp4j.Snmp;
import org.snmp4j.TransportMapping;
import org.snmp4j.mp.MPv1;
import org.snmp4j.mp.MPv2c;
import org.snmp4j.mp.MPv3;
import org.snmp4j.security.SecurityProtocols;
import org.snmp4j.security.USM;
import org.snmp4j.smi.OctetString;
import org.snmp4j.transport.DefaultUdpTransportMapping;
import org.vertx.java.core.Handler;


public class SnmpLink {
	
	private Node node;
	private Snmp snmp;
	
	private SnmpLink(Node node) {
		this.node = node;
	}
	
	public static void start(Node parent) {
		Node node = parent.createChild("snmp").build();
		final SnmpLink link = new SnmpLink(node);
		link.init();
	}
	
	private void init() {
		Action act = new Action(Permission.READ, new AddAgentHandler());
		act.addParameter(new Parameter("ip", ValueType.STRING));
		act.addParameter(new Parameter("name", ValueType.STRING));
		node.createChild("addAgent").setAction(act).build();
		
		try {
			TransportMapping transport = new DefaultUdpTransportMapping();
			snmp = new Snmp(transport);
			SecurityProtocols.getInstance().addDefaultProtocols();
			MessageDispatcher disp = snmp.getMessageDispatcher();
			disp.addMessageProcessingModel(new MPv1());
			disp.addMessageProcessingModel(new MPv2c());
			OctetString localEngineID = new OctetString(MPv3.createLocalEngineID());
			    // For command generators, you may use the following code to avoid
			    // engine ID clashes:
			    // MPv3.createLocalEngineID(
			    //   new OctetString("MyUniqueID"+System.currentTimeMillis())));
			USM usm = new USM(SecurityProtocols.getInstance(), localEngineID, 0);
			disp.addMessageProcessingModel(new MPv3(usm));
			snmp.listen();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	private class AddAgentHandler implements Handler<ActionResult> {
		public void handle(ActionResult event) {
			String ip = event.getParameter("ip", ValueType.STRING).getString();
			String name = event.getParameter("name", ValueType.STRING).getString();
			new AgentNode(snmp, node, ip, name);
			
		}
	}

}
