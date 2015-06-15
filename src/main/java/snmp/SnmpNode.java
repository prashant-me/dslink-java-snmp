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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.snmp4j.PDU;
import org.snmp4j.Snmp;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.event.ResponseListener;
import org.snmp4j.smi.AbstractVariable;
import org.snmp4j.smi.AssignableFromString;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.SMIConstants;
import org.snmp4j.smi.Variable;
import org.snmp4j.smi.VariableBinding;
import org.vertx.java.core.Handler;

public class SnmpNode {
	static private final Logger LOGGER;
	
	protected Node node;
	protected SnmpLink link;
	protected Snmp snmp;
	protected AgentNode root;
	
	SnmpNode(SnmpLink slink, Node mynode) {
		link = slink;
		node = mynode;
		node.setAttribute("restoreType", new Value("folder"));
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
		act.addParameter(new Parameter("OID", ValueType.STRING, new Value("0.0")));
		node.createChild("walk").setAction(act).build().setSerializable(false);
	}
	
	SnmpNode(SnmpLink slink, Node mynode, AgentNode anode) {
		this(slink, mynode);
		this.root = anode;
	}
	
	static {
        LOGGER = LoggerFactory.getLogger(SnmpLink.class);
    }
	
	class WalkHandler implements Handler<ActionResult> {
		public void handle(ActionResult event) {
			final String name = event.getParameter("name", ValueType.STRING).getString();
			String oid = event.getParameter("OID", ValueType.STRING).getString();
			if (oid.charAt(0)=='.') oid = oid.substring(1);
			Node response = node.createChild(name).build();
			Action act = new Action(Permission.READ, new Handler<ActionResult>() {
				public void handle(ActionResult event) {
					node.removeChild(name);
				}
			});
			response.createChild("remove").setAction(act).build().setSerializable(false);
			response.setAttribute("restoreType", new Value("walk"));
			walk(response, new OID(oid));
		}
	}
	
	private void walk(final Node response, final OID oid) {
		PDU pdu = new PDU();
		pdu.add(new VariableBinding(oid));
		pdu.setType(PDU.GETNEXT);
		ResponseListener listener = new ResponseListener() {
		     public void onResponse(ResponseEvent event) {
		    	 LOGGER.info("Received response PDU is: "+event.getResponse());
		    	 LOGGER.info("Received response PDU Error is: "+event.getError());
		    	 LOGGER.info("Received response PDU Peer Address is: "+event.getPeerAddress());
		       ((Snmp)event.getSource()).cancel(event.getRequest(), this);
		       //LOGGER.info("(Walking) Received response PDU is: "+event.getResponse());
		       if (event.getResponse() != null && !event.getResponse().get(0).isException()) {
		    	   OID noid = event.getResponse().get(0).getOid();
		    	   String val = event.getResponse().getVariable(noid).toString();
		    	   String noidname = link.parseOid(noid);
		    	   NodeBuilder builder = response.createChild(noidname.replace('.', ','));
		    	   builder.setValueType(ValueType.STRING);
		    	   builder.setValue(new Value(val));
		    	   Node vnode = builder.build();
		    	   vnode.setAttribute("oid", new Value(noid.toString()));
		    	   vnode.setAttribute("syntax", new Value(event.getResponse().getVariable(noid).getSyntax()));
		    	   createOidActions(vnode);
		    	   link.setupOID(vnode, root);
		    	   walk(response, noid);
		       }
		     }
		   };
		try {
			LOGGER.info("sending getnext");
			LOGGER.info("sending pdu: " + pdu + "   to target: " + root.target);
			snmp.send(pdu, root.target, null, listener);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			//e.printStackTrace();
			LOGGER.error("error:", e);
		}
	}
	
	class AddFolderHandler implements Handler<ActionResult> {
		public void handle(ActionResult event) {
			String name = event.getParameter("name", ValueType.STRING).getString();
			new SnmpNode(link, node.createChild(name).build(), root);
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
		    	 LOGGER.info("Received response PDU is: "+event.getResponse());
		    	 LOGGER.info("Received response PDU Error is: "+event.getError());
		    	 LOGGER.info("Received response PDU Peer Address is: "+event.getPeerAddress());
		       ((Snmp)event.getSource()).cancel(event.getRequest(), this);
		       //LOGGER.info("Received response PDU is: "+event.getResponse());
		       String val = "null";
		       if (event.getResponse() != null) {
		    	   val = event.getResponse().getVariable(new OID(oid)).toString();
		    	   response.setAttribute("syntax", new Value(event.getResponse().getVariable(new OID(oid)).getSyntax()));
		       }
		       response.setValue(new Value(val));
		     }
		   };
		try {
			LOGGER.info("sending pdu: " + pdu + "   to target: " + root.target);
			snmp.send(pdu, root.target, null, listener);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			//e.printStackTrace();
			LOGGER.error("error:", e);
		}
	}
	
	void createOidActions(Node valnode) {
		Action act = new Action(Permission.READ, new RemoveOidHandler(valnode));
	    valnode.createChild("remove").setAction(act).build().setSerializable(false);
	    act = new Action(Permission.READ, new SetHandler(valnode));
	    act.addParameter(new Parameter("value", ValueType.STRING));
	    valnode.createChild("set").setAction(act).build().setSerializable(false);
	    
	}
	
	class SetHandler implements Handler<ActionResult> {
		private Node vnode;
		SetHandler(Node valnode) {
			vnode = valnode;
		}
		public void handle(ActionResult event) {
			PDU pdu = new PDU();
			Value oid = vnode.getAttribute("oid");
			Value syntax = vnode.getAttribute("syntax");
			if (oid == null || syntax == null) return;
			String valstring = event.getParameter("value", ValueType.STRING).getString();
			int syntaxInt = syntax.getNumber().intValue();
			if (syntaxInt == SMIConstants.SYNTAX_NULL) return;
			Variable val = AbstractVariable.createFromSyntax(syntaxInt);
			if (!(val instanceof AssignableFromString)) return;
			((AssignableFromString) val).setValue(valstring);
			pdu.add(new VariableBinding(new OID(oid.getString()), val));
			
//			try {
//				pdu.add(new VariableBinding(new OID(oid), val));
//			} catch (ParseException e) {
//				// TODO Auto-generated catch block
//				LOGGER.error("Error parsing value string");
//				e.printStackTrace();
//				LOGGER.debug("error:", e);
//				return;
//			}
			pdu.setType(PDU.SET);
			try {
				LOGGER.debug("sending pdu: " + pdu + "   to target: " + root.target);
				snmp.send(pdu, root.target, null, null);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				//e.printStackTrace();
				LOGGER.debug("error:", e);
			}
			
		}
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
		if (node.getChildren() == null) return;
		for  (Node child: node.getChildren().values()) {
			Value restoreType = child.getAttribute("restoreType");
			if (restoreType != null && restoreType.getString().equals("folder")) {
				SnmpNode sn = new SnmpNode(link, child, root);
				sn.restoreLastSession();
			} else if (restoreType != null && restoreType.getString().equals("walk")) {
				if (child.getChildren() != null) {
					for (Node subchild: child.getChildren().values()) {
						if (subchild.getValue() != null) {
							createOidActions(subchild);
							link.setupOID(subchild, root);
						}
					}
				}
				final String name = child.getName();
				Action act = new Action(Permission.READ, new Handler<ActionResult>() {
					public void handle(ActionResult event) {
						node.removeChild(name);
					}
				});
				child.createChild("remove").setAction(act).build().setSerializable(false);
			} else if (child.getValue() != null) {
				if (root == this && child.getName() == "TRAPS") {
					
				} else {
					createOidActions(child);
					link.setupOID(child, root);
				}
			} else if (child.getAction() == null) {
				node.removeChild(child);
			}
		}
	}
	
	
}
