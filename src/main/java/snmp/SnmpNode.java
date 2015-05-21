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
	protected SnmpLink link;
	protected Snmp snmp;
	protected CommunityTarget target;
	protected AgentNode root;
	
	SnmpNode(SnmpLink slink, Node mynode) {
		link = slink;
		node = mynode;
		node.setAttribute("restorable", new Value(true));
		this.snmp = link.snmp;
		
		Action act = new Action(Permission.READ, new GetHandler());
		act.addParameter(new Parameter("name", ValueType.STRING));
		act.addParameter(new Parameter("OID", ValueType.STRING));
		node.createChild("addOID").setAction(act).build().setSerializable(false);
		act = new Action(Permission.READ, new RemoveHandler());
		node.createChild("remove").setAction(act).build().setSerializable(false);
		act = new Action(Permission.READ, new AddFolderHandler());
		act.addParameter(new Parameter("name", ValueType.STRING));
		node.createChild("addFolder").setAction(act).build().setSerializable(false);
		act = new Action(Permission.READ, new WalkHandler());
		act.addParameter(new Parameter("name", ValueType.STRING));
		act.addParameter(new Parameter("OID", ValueType.STRING));
		node.createChild("walk").setAction(act).build().setSerializable(false);
	}
	
	SnmpNode(SnmpLink slink, Node mynode, CommunityTarget target, AgentNode anode) {
		this(slink, mynode);
		this.target = target;
		this.root = anode;
	}
	
	class WalkHandler implements Handler<ActionResult> {
		public void handle(ActionResult event) {
			final String name = event.getParameter("name", ValueType.STRING).getString();
			String oid = event.getParameter("OID", ValueType.STRING).getString();
			if (oid.charAt(0)=='.') oid = oid.substring(1);
			Node response = node.createChild(name).build();
			walk(response, new OID(oid));
		}
	}
	
	private void walk(final Node response, final OID oid) {
		PDU pdu = new PDU();
		pdu.add(new VariableBinding(oid));
		pdu.setType(PDU.GETNEXT);
		ResponseListener listener = new ResponseListener() {
		     public void onResponse(ResponseEvent event) {
		       ((Snmp)event.getSource()).cancel(event.getRequest(), this);
		       System.out.println("Received response PDU is: "+event.getResponse());
		       if (event.getResponse() != null && !event.getResponse().get(0).isException()) {
		    	   OID noid = event.getResponse().get(0).getOid();
		    	   String val = event.getResponse().getVariable(noid).toString();
		    	   NodeBuilder builder = response.createChild(noid.toDottedString().replace('.', ','));
		    	   builder.setValueType(ValueType.STRING);
		    	   builder.setValue(new Value(val));
		    	   Node vnode = builder.build();
		    	   vnode.setAttribute("oid", new Value(noid.toString()));
		    	   createOidActions(vnode);
		    	   link.setupOID(vnode, root);
		    	   walk(response, noid);
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
	
	class AddFolderHandler implements Handler<ActionResult> {
		public void handle(ActionResult event) {
			String name = event.getParameter("name", ValueType.STRING).getString();
			new SnmpNode(link, node.createChild(name).build(), target, root);
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
			if (oid.charAt(0)=='.') oid = oid.substring(1);
			NodeBuilder builder = node.createChild(name);
	    	builder.setValueType(ValueType.STRING);
	    	Node response = builder.build();
	    	response.setAttribute("oid", new Value(oid));
		    createOidActions(response);
		    link.setupOID(response, root);
		}
	}
	
	void sendGetRequest(final Node response) {
		PDU pdu = new PDU();
		final String oid = response.getAttribute("oid").getString();
		pdu.add(new VariableBinding(new OID(oid)));
		pdu.setType(PDU.GET);
		ResponseListener listener = new ResponseListener() {
		     public void onResponse(ResponseEvent event) {
		       ((Snmp)event.getSource()).cancel(event.getRequest(), this);
		       System.out.println("Received response PDU is: "+event.getResponse());
		       String val = "null";
		       if (event.getResponse() != null) val = event.getResponse().getVariable(new OID(oid)).toString();
		       response.setValue(new Value(val));
		     }
		   };
		try {
			snmp.send(pdu, target, null, listener);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	void createOidActions(Node valnode) {
		Action act = new Action(Permission.READ, new RemoveOidHandler(valnode));
	    valnode.createChild("remove").setAction(act).build().setSerializable(false);
//	    Action act = new Action(Permission.READ, new SetHandler());
//	    valnode.createChild("set").setAction(act).build().setSerializable(false);
//	    valnode.setWritable(Writable.WRITE);
	    //valnode.getListener().setValueHandler(handler);
	    
	}
	
	class RemoveOidHandler implements Handler<ActionResult> {
		Node toRemove;
		RemoveOidHandler(Node valnode) {
			toRemove = valnode;
		}
		public void handle(ActionResult event) {
			node.removeChild(toRemove);
		}
		
	}
	
	void restoreLastSession() {
		for  (Node child: node.getChildren().values()) {
			Value restorable = child.getAttribute("restorable");
			if (restorable != null && restorable.getBool() == true) {
				SnmpNode sn = new SnmpNode(link, child, target, root);
				sn.restoreLastSession();
			} else if (child.getValue() != null) {
				createOidActions(child);
				link.setupOID(child, root);
			} else if (child.getAction() == null) {
				node.removeChild(child);
			}
		}
	}
	
	
}
