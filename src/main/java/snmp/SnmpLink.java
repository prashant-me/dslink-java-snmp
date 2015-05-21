package snmp;


import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import org.dsa.iot.dslink.node.Node;
import org.dsa.iot.dslink.node.NodeBuilder;
import org.dsa.iot.dslink.node.Permission;
import org.dsa.iot.dslink.node.actions.Action;
import org.dsa.iot.dslink.node.actions.ActionResult;
import org.dsa.iot.dslink.node.actions.Parameter;
import org.dsa.iot.dslink.node.value.Value;
import org.dsa.iot.dslink.node.value.ValueType;
import org.dsa.iot.dslink.util.Objects;
import org.snmp4j.MessageDispatcher;
import org.snmp4j.Snmp;
import org.snmp4j.TransportMapping;
import org.snmp4j.mp.MPv1;
import org.snmp4j.mp.MPv2c;
import org.snmp4j.mp.MPv3;
import org.snmp4j.security.SecurityProtocols;
import org.snmp4j.security.USM;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.UdpAddress;
import org.snmp4j.transport.DefaultUdpTransportMapping;
import org.vertx.java.core.Handler;


public class SnmpLink {
	
	private Node node;
	Snmp snmp;
	private final Map<Node, ScheduledFuture<?>> futures;
	
	private SnmpLink(Node node) {
		this.node = node;
		this.futures = new ConcurrentHashMap<>();
	}
	
	public static void start(Node parent) {
		Node node = parent.createChild("snmp").build();
		final SnmpLink link = new SnmpLink(node);
		link.init();
	}
	
	private void init() {
		
		try {
			TransportMapping<UdpAddress> transport = new DefaultUdpTransportMapping();
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
		
		restoreLastSession();
		
		Action act = new Action(Permission.READ, new AddAgentHandler());
		act.addParameter(new Parameter("name", ValueType.STRING));
		act.addParameter(new Parameter("ip", ValueType.STRING));
		act.addParameter(new Parameter("refreshInterval", ValueType.NUMBER));
		NodeBuilder b = node.createChild("addAgent");
		b.setAction(act);
		Node n = b.build();
		n.setSerializable(false);
		
	}
	
	private void restoreLastSession() {
		if (node.getChildren() == null) return;
		for (Node child: node.getChildren().values()) {
			Value ip = child.getAttribute("ip");
			Value interval = child.getAttribute("interval");
			if (ip != null && interval != null) {
				AgentNode an = new AgentNode(this, child, ip.getString(), interval.getNumber().longValue());
				an.restoreLastSession();
			} else if (child.getAction() == null) {
				node.removeChild(child);
			}
		}
	}
	
	private class AddAgentHandler implements Handler<ActionResult> {
		public void handle(ActionResult event) {
			String ip = event.getParameter("ip", ValueType.STRING).getString();
			String name = event.getParameter("name", ValueType.STRING).getString();
			long interval = event.getParameter("refreshInterval", ValueType.NUMBER).getNumber().longValue();
			Node child = node.createChild(name).build();
			new AgentNode(getMe(), child, ip, interval);
		}
	}
	

	
    void setupOID(Node child, final AgentNode agent) {
        child.getListener().setOnSubscribeHandler(new Handler<Node>() {
            public void handle(final Node event) {
                if (futures.containsKey(event)) {
                    return;
                }
                ScheduledThreadPoolExecutor stpe = Objects.getDaemonThreadPool();
                ScheduledFuture<?> fut = stpe.scheduleWithFixedDelay(new Runnable() {
                    @Override
                    public void run() {
                    	if (event.getAttribute("oid") != null) agent.sendGetRequest(event);
                    }
                }, 0, agent.interval, TimeUnit.SECONDS);
                futures.put(event, fut);
            }
        });

        child.getListener().setOnUnsubscribeHandler(new Handler<Node>() {
            @Override
            public void handle(Node event) {
                ScheduledFuture<?> fut = futures.remove(event);
                if (fut != null) {
                    fut.cancel(false);
                }
            }
        });
    }
	
	private SnmpLink getMe() {
		return this;
	}

}
