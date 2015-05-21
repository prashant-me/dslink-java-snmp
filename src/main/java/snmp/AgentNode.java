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
	
	AgentNode(SnmpLink slink, Node mynode, String ip, long interval) {
		super(slink, mynode);
		root = this;
		this.interval = interval;
		node.setAttribute("interval", new Value(this.interval));
		node.setAttribute("ip", new Value(ip));
		Node tnode = node.createChild("TRAPS").setValueType(ValueType.STRING).build();
		String emptyjson = new JsonArray().toString();
		tnode.setValue(new Value(emptyjson));
		
		setTarget(ip);
		
		Action act = new Action(Permission.READ, new EditAgentHandler());
		act.addParameter(new Parameter("ip", ValueType.STRING, new Value(ip.split("/")[0])));
		act.addParameter(new Parameter("port", ValueType.STRING, new Value(ip.split("/")[1])));
		act.addParameter(new Parameter("refreshInterval", ValueType.NUMBER, new Value(interval)));
		node.createChild("edit").setAction(act).build().setSerializable(false);
	}
	
	class EditAgentHandler implements Handler<ActionResult> {
		public void handle(ActionResult event) {
			String ip = event.getParameter("ip", ValueType.STRING).getString() + "/" 
					+ event.getParameter("port", ValueType.STRING).getString();
			interval = event.getParameter("refreshInterval", ValueType.NUMBER).getNumber().longValue();
			node.setAttribute("interval", new Value(interval));
			node.setAttribute("ip", new Value(ip));
			setTarget(ip);
			
		}
	}
	
	protected void setTarget(String ip) {
		target = new CommunityTarget();
		target.setCommunity(new OctetString("public"));
		Address ad = GenericAddress.parse("udp:"+ip);
		target.setAddress(ad);
		target.setRetries(5);
		target.setTimeout(5500);
		target.setVersion(SnmpConstants.version2c);
	}
	
	
	
}
