package snmp;

import org.dsa.iot.dslink.node.Node;
import org.dsa.iot.dslink.node.value.Value;
import org.snmp4j.CommunityTarget;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.GenericAddress;
import org.snmp4j.smi.OctetString;

class AgentNode extends SnmpNode {
	
	long interval;
	
	AgentNode(SnmpLink slink, Node mynode, String ip, long interval) {
		super(slink, mynode);
		root = this;
		this.interval = interval;
		node.setAttribute("interval", new Value(this.interval));
		
				
		node.setAttribute("ip", new Value(ip));
		
		target = new CommunityTarget();
		target.setCommunity(new OctetString("public"));
		Address ad = GenericAddress.parse("udp:"+ip);
		target.setAddress(ad);
		target.setRetries(5);
		target.setTimeout(5500);
		target.setVersion(SnmpConstants.version2c);
		
		
	}
	
	
	
	
	
}
