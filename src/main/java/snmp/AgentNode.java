package snmp;


import org.dsa.iot.dslink.node.Node;
import org.dsa.iot.dslink.node.Permission;
import org.dsa.iot.dslink.node.actions.Action;
import org.dsa.iot.dslink.node.actions.ActionResult;
import org.dsa.iot.dslink.node.actions.Parameter;
import org.dsa.iot.dslink.node.value.Value;
import org.dsa.iot.dslink.node.value.ValueType;
import org.snmp4j.CommunityTarget;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.GenericAddress;
import org.snmp4j.smi.OctetString;
import org.vertx.java.core.Handler;
import org.vertx.java.core.json.JsonArray;

class AgentNode extends SnmpNode {
	
	long interval;
	CommunityTarget target;
	
	AgentNode(SnmpLink slink, Node mynode, String ip, long interval, String comString, int retries, long timeout) {
		super(slink, mynode);
		root = this;
		this.interval = interval;
		node.setAttribute("interval", new Value(this.interval));
		node.setAttribute("ip", new Value(ip));
		node.setAttribute("communityString", new Value(comString));
		node.setAttribute("retries", new Value(retries));
		node.setAttribute("timeout", new Value(timeout));
		Node tnode = node.createChild("TRAPS").setValueType(ValueType.STRING).build();
		String emptyjson = new JsonArray().toString();
		tnode.setValue(new Value(emptyjson));
		
		setTarget(ip, comString, retries, timeout);
		
		makeEditAction(ip, interval, comString, retries, timeout);
	}
	
	private void makeEditAction(String ip, long interval, String comString, int retries, long timeout) {
		Action act = new Action(Permission.READ, new EditAgentHandler());
		act.addParameter(new Parameter("ip", ValueType.STRING, new Value(ip.split("/")[0])));
		act.addParameter(new Parameter("port", ValueType.STRING, new Value(ip.split("/")[1])));
		act.addParameter(new Parameter("refreshInterval", ValueType.NUMBER, new Value(interval)));
		act.addParameter(new Parameter("communityString", ValueType.STRING, new Value(comString)));
		act.addParameter(new Parameter("retries", ValueType.NUMBER, new Value(retries)));
		act.addParameter(new Parameter("Timeout", ValueType.NUMBER, new Value(timeout)));
		node.createChild("edit").setAction(act).build().setSerializable(false);
	}
	
	class EditAgentHandler implements Handler<ActionResult> {
		public void handle(ActionResult event) {
			String ip = event.getParameter("ip", ValueType.STRING).getString() + "/" 
					+ event.getParameter("port", ValueType.STRING).getString();
			interval = event.getParameter("refreshInterval", ValueType.NUMBER).getNumber().longValue();
			String comStr = event.getParameter("communityString", ValueType.STRING).getString();
			int retries = event.getParameter("retries", ValueType.NUMBER).getNumber().intValue();
			long timeout = event.getParameter("Timeout", ValueType.NUMBER).getNumber().longValue();
			node.setAttribute("interval", new Value(interval));
			node.setAttribute("ip", new Value(ip));
			node.setAttribute("communityString", new Value(comStr));
			node.setAttribute("retries", new Value(retries));
			node.setAttribute("timeout", new Value(timeout));
			setTarget(ip, comStr, retries, timeout);
			node.removeChild("edit");
			makeEditAction(ip, interval, comStr, retries, timeout);
			
		}
	}
	
	protected void setTarget(String ip, String comString, int retries, long timeout) {
		target = new CommunityTarget();
		target.setCommunity(new OctetString(comString));
		Address ad = GenericAddress.parse("udp:"+ip);
		target.setAddress(ad);
		target.setRetries(retries);
		target.setTimeout(timeout);
		target.setVersion(SnmpConstants.version2c);
	}
	
	
	
}
