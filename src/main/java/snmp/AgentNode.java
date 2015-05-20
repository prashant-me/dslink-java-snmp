package snmp;

import org.dsa.iot.dslink.node.Node;
import org.snmp4j.CommunityTarget;
import org.snmp4j.Snmp;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.GenericAddress;
import org.snmp4j.smi.OctetString;

class AgentNode extends SnmpNode {
	
	
	AgentNode(Snmp snmp, Node parent, String ip, String name) {
		super(snmp, parent, name);
	
		target = new CommunityTarget();
		target.setCommunity(new OctetString("public"));
		Address ad = GenericAddress.parse("udp:"+ip);
		target.setAddress(ad);
		target.setRetries(5);
		target.setTimeout(5500);
		target.setVersion(SnmpConstants.version2c);
		
		
	}
	
	
	
	
	
}
