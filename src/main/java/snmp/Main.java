package snmp;


import org.dsa.iot.dslink.DSLink;
import org.dsa.iot.dslink.DSLinkFactory;
import org.dsa.iot.dslink.DSLinkHandler;
import org.dsa.iot.dslink.node.Node;
import org.dsa.iot.dslink.node.NodeManager;

public class Main extends DSLinkHandler {
	
	public static void main(String[] args) {
		
		args = new String[] { "-b", "http://localhost:8080/conn" };
		DSLinkFactory.startResponder("snmpResponder", args, new Main());
	}
	
	@Override
	public void onResponderConnected(DSLink link){
		NodeManager manager = link.getNodeManager();
        Node superRoot = manager.getNode("/").getNode();
        //SubscriptionManager submanager = link.getSubscriptionManager();
        SnmpLink.start(superRoot);
	}

}
