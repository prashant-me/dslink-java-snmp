package snmp;


import org.dsa.iot.dslink.node.Node;
import org.dsa.iot.dslink.node.Permission;
import org.dsa.iot.dslink.node.actions.Action;
import org.dsa.iot.dslink.node.actions.ActionResult;
import org.dsa.iot.dslink.node.actions.Parameter;
import org.dsa.iot.dslink.node.value.Value;
import org.dsa.iot.dslink.node.value.ValueType;
import org.snmp4j.CommunityTarget;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.GenericAddress;
import org.snmp4j.smi.OctetString;
import org.vertx.java.core.Handler;
import org.vertx.java.core.json.JsonArray;

import snmp.SnmpLink.SnmpVersion;

class AgentNode extends SnmpNode {
	
	long interval;
	CommunityTarget target;
	
	AgentNode(SnmpLink slink, Node mynode, String ip, long interval, String comString, SnmpVersion version, int retries, long timeout) {
		super(slink, mynode);
		root = this;
		this.interval = interval;
		node.setAttribute("Refresh Interval", new Value(this.interval));
		node.setAttribute("IP", new Value(ip));
		node.setAttribute("Community String", new Value(comString));
		node.setAttribute("SNMP Version", new Value(version.toString()));
		node.setAttribute("Retries", new Value(retries));
		node.setAttribute("Timeout", new Value(timeout));
		//node.setAttribute("securityLevel", new Value(securityLevel));
		final Node tnode = node.createChild("TRAPS").setValueType(ValueType.STRING).build();
		String emptyjson = new JsonArray().toString();
		tnode.setValue(new Value(emptyjson));
		Action act = new Action(Permission.READ, new Handler<ActionResult>() {
			public void handle(ActionResult event) {
				tnode.setValue(new Value(new JsonArray().toString()));
			}
		});
		tnode.createChild("clear").setAction(act).build().setSerializable(false);
		
		setTarget(ip, comString, version, retries, timeout);
		
		makeEditAction(ip, interval, comString, version, retries, timeout);
	}
	
	private void makeEditAction(String ip, long interval, String comString, SnmpVersion version, int retries, long timeout) {
		Action act = new Action(Permission.READ, new EditAgentHandler());
		act.addParameter(new Parameter("IP", ValueType.STRING, new Value(ip.split("/")[0])));
		act.addParameter(new Parameter("Port", ValueType.STRING, new Value(ip.split("/")[1])));
		act.addParameter(new Parameter("Refresh Interval", ValueType.NUMBER, new Value(interval)));
		act.addParameter(new Parameter("Community String", ValueType.STRING, new Value(comString)));
		act.addParameter(new Parameter("SNMP Version", ValueType.makeEnum("1", "2c"), new Value(version.toString())));
		act.addParameter(new Parameter("Retries", ValueType.NUMBER, new Value(retries)));
		act.addParameter(new Parameter("Timeout", ValueType.NUMBER, new Value(timeout)));
		//act.addParameter(new Parameter("security level", ValueType.NUMBER, new Value(securityLevel)));
		node.createChild("edit").setAction(act).build().setSerializable(false);
	}
	
	class EditAgentHandler implements Handler<ActionResult> {
		public void handle(ActionResult event) {
			String ip = event.getParameter("IP", ValueType.STRING).getString() + "/" 
					+ event.getParameter("Port", ValueType.STRING).getString();
			interval = event.getParameter("Refresh Interval", ValueType.NUMBER).getNumber().longValue();
			String comStr = event.getParameter("Community String", ValueType.STRING).getString();
			SnmpVersion version = SnmpVersion.parse(event.getParameter("SNMP Version").getString());
			if (version == null) version = SnmpVersion.parse(node.getAttribute("SNMP Version").getString());
			if (version == null) version = SnmpVersion.v2c;
			int retries = event.getParameter("Retries", ValueType.NUMBER).getNumber().intValue();
			long timeout = event.getParameter("Timeout", ValueType.NUMBER).getNumber().longValue();
			//int securityLevel = event.getParameter("security level", ValueType.NUMBER).getNumber().intValue();
			node.setAttribute("Refresh Interval", new Value(interval));
			node.setAttribute("IP", new Value(ip));
			node.setAttribute("Community String", new Value(comStr));
			node.setAttribute("Retries", new Value(retries));
			node.setAttribute("Timeout", new Value(timeout));
			setTarget(ip, comStr, version, retries, timeout);
			node.removeChild("edit");
			makeEditAction(ip, interval, comStr, version, retries, timeout);
			
		}
	}
	
	protected void setTarget(String ip, String comString, SnmpVersion version, int retries, long timeout) {
		target = new CommunityTarget();
		target.setCommunity(new OctetString(comString));
		Address ad = GenericAddress.parse("udp:"+ip);
		target.setAddress(ad);
		target.setRetries(retries);
		target.setTimeout(timeout);
		target.setVersion(version.getVersion());
		//target.setSecurityLevel(securityLevel);
	}
	
	
	
}
