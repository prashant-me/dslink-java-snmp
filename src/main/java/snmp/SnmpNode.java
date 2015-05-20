package snmp;

import java.io.IOException;

import org.dsa.iot.dslink.node.Node;
import org.dsa.iot.dslink.node.NodeBuilder;
import org.dsa.iot.dslink.node.Permission;
import org.dsa.iot.dslink.node.actions.Action;
import org.dsa.iot.dslink.node.actions.ActionResult;
import org.dsa.iot.dslink.node.actions.Parameter;
import org.dsa.iot.dslink.node.value.Value;
import org.dsa.iot.dslink.node.value.ValueType;
import org.snmp4j.CommunityTarget;
import org.snmp4j.PDU;
import org.snmp4j.Snmp;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.event.ResponseListener;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.VariableBinding;
import org.vertx.java.core.Handler;

public class SnmpNode {
	
	protected Node node;
	protected Snmp snmp;
	protected CommunityTarget target;
	
	SnmpNode(Snmp snmp, Node parent, String name) {
		node = parent.createChild(name).build();
		this.snmp = snmp;
		
		Action act = new Action(Permission.READ, new GetHandler());
		act.addParameter(new Parameter("name", ValueType.STRING));
		act.addParameter(new Parameter("OID", ValueType.STRING));
		node.createChild("addOID").setAction(act).build();
		act = new Action(Permission.READ, new RemoveHandler());
		node.createChild("remove").setAction(act).build();
		act = new Action(Permission.READ, new AddFolderHandler());
		act.addParameter(new Parameter("name", ValueType.STRING));
		node.createChild("addFolder").setAction(act).build();
	}
	
	SnmpNode(Snmp snmp, Node parent, String name, CommunityTarget target) {
		this(snmp, parent, name);
		this.target = target;
	}
	
	class AddFolderHandler implements Handler<ActionResult> {
		public void handle(ActionResult event) {
			String name = event.getParameter("name", ValueType.STRING).getString();
			new SnmpNode(snmp, node, name, target);
		}
	}
	
	
	class RemoveHandler implements Handler<ActionResult> {
		public void handle(ActionResult event) {
			node.clearChildren();
			node.getParent().removeChild(node);
		}
		
	}
	
	class GetHandler implements Handler<ActionResult> {
		public void handle(ActionResult event) {
			final String name = event.getParameter("name", ValueType.STRING).getString();
			String oid = event.getParameter("OID", ValueType.STRING).getString();
			PDU pdu = new PDU();
			if (oid.charAt(0)=='.') oid = oid.substring(1);
			pdu.add(new VariableBinding(new OID(oid)));
			pdu.setType(PDU.GET);
			ResponseListener listener = new ResponseListener() {
			     public void onResponse(ResponseEvent event) {
			       ((Snmp)event.getSource()).cancel(event.getRequest(), this);
			       System.out.println("Received response PDU is: "+event.getResponse());
			       String val = "null";
			       if (event.getResponse() != null) val = event.getResponse().toString();
			       Node response = node.getChild(name);
			       if (response == null) {
			    	   NodeBuilder builder = node.createChild(name);
			    	   builder.setValueType(ValueType.STRING);
			    	   builder.setValue(new Value(val));
			    	   builder.build();
			       } else {
			    	   response.setValue(new Value(val));
			       }
			     }
			   };
			try {
				snmp.send(pdu, target, null, listener);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}
	
	
}
