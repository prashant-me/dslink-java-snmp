package snmp;


import org.dsa.iot.dslink.node.Node;
import org.dsa.iot.dslink.node.Permission;
import org.dsa.iot.dslink.node.actions.Action;
import org.dsa.iot.dslink.node.actions.ActionResult;
import org.dsa.iot.dslink.node.actions.Parameter;
import org.dsa.iot.dslink.node.value.Value;
import org.dsa.iot.dslink.node.value.ValueType;
import org.snmp4j.CommunityTarget;
import org.snmp4j.UserTarget;
import org.snmp4j.security.AuthMD5;
import org.snmp4j.security.AuthSHA;
import org.snmp4j.security.PrivAES128;
import org.snmp4j.security.PrivAES192;
import org.snmp4j.security.PrivAES256;
import org.snmp4j.security.PrivDES;
import org.snmp4j.security.SecurityLevel;
import org.snmp4j.security.UsmUser;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.GenericAddress;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.vertx.java.core.Handler;
import org.vertx.java.core.json.JsonArray;

import snmp.SnmpLink.SnmpVersion;

class AgentNode extends SnmpNode {
	
	long interval;
	CommunityTarget target;
	
	AgentNode(SnmpLink slink, Node mynode) {
		super(slink, mynode);
		root = this;
		this.interval = node.getAttribute("Polling Interval").getNumber().longValue();

		final Node tnode = node.createChild("TRAPS").setValueType(ValueType.STRING).build();
		String emptyjson = new JsonArray().toString();
		tnode.setValue(new Value(emptyjson));
		Action act = new Action(Permission.READ, new Handler<ActionResult>() {
			public void handle(ActionResult event) {
				tnode.setValue(new Value(new JsonArray().toString()));
			}
		});
		tnode.createChild("clear").setAction(act).build().setSerializable(false);
		
		makeEditAction();
		
		setTarget();
		
	}
	
	private void makeEditAction() {
		Action act = new Action(Permission.READ, new EditAgentHandler());
		String ip = node.getAttribute("ip").getString();
		act.addParameter(new Parameter("IP", ValueType.STRING, new Value(ip.split("/")[0])));
		act.addParameter(new Parameter("Port", ValueType.STRING, new Value(ip.split("/")[1])));
		act.addParameter(new Parameter("Polling Interval", ValueType.NUMBER, new Value(interval)));
		act.addParameter(new Parameter("Community String", ValueType.STRING, node.getAttribute("Community String")));
		act.addParameter(new Parameter("SNMP Version", ValueType.makeEnum("1", "2c", "3"), node.getAttribute("SNMP Version")));
		act.addParameter(new Parameter("Security Name", ValueType.STRING, node.getAttribute("Security Name")));
		act.addParameter(new Parameter("Auth Protocol", ValueType.makeEnum("NONE", "MD5", "SHA"), node.getAttribute("Auth Protocol")));
		act.addParameter(new Parameter("Auth Passphrase", ValueType.STRING, node.getAttribute("Auth Passphrase")));
		act.addParameter(new Parameter("Priv Protocol", ValueType.makeEnum("NONE", "DES", "AES128", "AES192", "AES256"), node.getAttribute("Priv Protocol")));
		act.addParameter(new Parameter("Priv Passphrase", ValueType.STRING, node.getAttribute("Priv Passphrase")));
		act.addParameter(new Parameter("Engine ID", ValueType.STRING, node.getAttribute("Engine ID")));
		act.addParameter(new Parameter("Context Engine", ValueType.STRING, node.getAttribute("Context Engine")));
		act.addParameter(new Parameter("Context Name", ValueType.STRING, node.getAttribute("Context Name")));
		act.addParameter(new Parameter("Retries", ValueType.NUMBER, node.getAttribute("Retries")));
		act.addParameter(new Parameter("Timeout", ValueType.NUMBER, node.getAttribute("Timeout")));
		node.createChild("edit").setAction(act).build().setSerializable(false);
	}
	
	class EditAgentHandler implements Handler<ActionResult> {
		public void handle(ActionResult event) {
			String ip = event.getParameter("IP", ValueType.STRING).getString() + "/" 
					+ event.getParameter("Port", ValueType.STRING).getString();
			interval = event.getParameter("Polling Interval", ValueType.NUMBER).getNumber().longValue();
			String comStr = event.getParameter("Community String", ValueType.STRING).getString();
			SnmpVersion version = SnmpVersion.parse(event.getParameter("SNMP Version").getString());
			if (version == null) version = SnmpVersion.parse(node.getAttribute("SNMP Version").getString());
			if (version == null) version = SnmpVersion.v2c;
			String secName = event.getParameter("Security Name", ValueType.STRING).getString();
			String authProt = event.getParameter("Auth Protocol").getString();
			String authPass = event.getParameter("Auth Passphrase", ValueType.STRING).getString();
			String privProt = event.getParameter("Priv Protocol").getString();
			String privPass = event.getParameter("Priv Passphrase", ValueType.STRING).getString();
			String engine = event.getParameter("Engine ID", ValueType.STRING).getString();
			String cEngine = event.getParameter("Context Engine", ValueType.STRING).getString();
			String cName = event.getParameter("Context Name", ValueType.STRING).getString();
			int retries = event.getParameter("Retries", ValueType.NUMBER).getNumber().intValue();
			long timeout = event.getParameter("Timeout", ValueType.NUMBER).getNumber().longValue();
			
			node.setAttribute("Polling Interval", new Value(interval));
			node.setAttribute("IP", new Value(ip));
			node.setAttribute("SNMP Version", new Value(version.toString()));
			node.setAttribute("Community String", new Value(comStr));
			node.setAttribute("Security Name", new Value(secName));
			node.setAttribute("Auth Protocol", new Value(authProt));
			node.setAttribute("Auth Passphrase", new Value(authPass));
			node.setAttribute("Priv Protocol", new Value(privProt));
			node.setAttribute("Priv Passphrase", new Value(privPass));
			node.setAttribute("Engine ID", new Value(engine));
			node.setAttribute("Context Engine", new Value(cEngine));
			node.setAttribute("Context Name", new Value(cName));
			node.setAttribute("Retries", new Value(retries));
			node.setAttribute("Timeout", new Value(timeout));
			setTarget();
			node.removeChild("edit");
			makeEditAction();
			
		}
	}
	
	public SnmpVersion getVersion() {
		SnmpVersion v = SnmpVersion.parse(node.getAttribute("SNMP Version").getString());
		if (v==null) v = SnmpVersion.v2c;
		return v;
	}
	
	protected void setTarget() {
		if (snmp.getUSM() != null) snmp.getUSM().removeAllUsers();
		String ip = node.getAttribute("ip").getString();
		String comString = node.getAttribute("Community String").getString();
		SnmpVersion version = SnmpVersion.parse(node.getAttribute("SNMP Version").getString());
		if (version == null) version = SnmpVersion.v2c;
		int retries = node.getAttribute("Retries").getNumber().intValue();
		long timeout = node.getAttribute("Timeout").getNumber().longValue();
		
		if (version == SnmpVersion.v3) {
			String authProtocolStr = node.getAttribute("Auth Protocol").getString();
			String privProtocolStr = node.getAttribute("Priv Protocol").getString();
			OctetString securityName = createOctetString(node.getAttribute("Security Name").getString());
			OID authProtocol = null;
			OID privProtocol = null;
			if (authProtocolStr.length() > 0 && !authProtocolStr.equals("NONE")) {
	            if (authProtocolStr.equals("MD5"))
	                authProtocol = AuthMD5.ID;
	            else if (authProtocolStr.equals("SHA"))
	                authProtocol = AuthSHA.ID;
	            else
	                throw new IllegalArgumentException("Authentication protocol unsupported: " + authProtocolStr);
	        }

	        OctetString authPassphrase = createOctetString(node.getAttribute("Auth Passphrase").getString());

	        if (privProtocolStr.length() > 0 && !privProtocolStr.equals("NONE")) {
	            if (privProtocolStr.equals("DES"))
	                privProtocol = PrivDES.ID;
	            else if ((privProtocolStr.equals("AES128")) || (privProtocolStr.equals("AES")))
	                privProtocol = PrivAES128.ID;
	            else if (privProtocolStr.equals("AES192"))
	                privProtocol = PrivAES192.ID;
	            else if (privProtocolStr.equals("AES256"))
	                privProtocol = PrivAES256.ID;
	            else
	                throw new IllegalArgumentException("Privacy protocol " + privProtocolStr + " not supported");
	        }

	        OctetString privPassphrase = createOctetString(node.getAttribute("Priv Passphrase").getString());
			OctetString engineId = createOctetString(node.getAttribute("Engine ID").getString());
	        
			if (engineId != null) snmp.setLocalEngine(engineId.getValue(), 0, 0);
		    snmp.getUSM().addUser(securityName,
		                new UsmUser(securityName, authProtocol, authPassphrase, privProtocol, privPassphrase));
		    
		    UserTarget target = new UserTarget();
	        if (authPassphrase.length() > 0) {
	            if (privPassphrase.length() > 0)
	                target.setSecurityLevel(SecurityLevel.AUTH_PRIV);
	            else
	                target.setSecurityLevel(SecurityLevel.AUTH_NOPRIV);
	        }
	        else
	            target.setSecurityLevel(SecurityLevel.NOAUTH_NOPRIV);

	        target.setSecurityName(securityName);
		    
		} else {
			target = new CommunityTarget();
			target.setCommunity(new OctetString(comString));
		}
		
		Address ad = GenericAddress.parse("udp:"+ip);
		target.setAddress(ad);
		target.setRetries(retries);
		target.setTimeout(timeout);
		target.setVersion(version.getVersion());
	}
	
    public static OctetString createOctetString(String s) {
        OctetString octetString;

        if (s.startsWith("0x"))
            octetString = OctetString.fromHexString(s.substring(2), ':');
        else
            octetString = new OctetString(s);

        return octetString;
    }
	
	
	
}
