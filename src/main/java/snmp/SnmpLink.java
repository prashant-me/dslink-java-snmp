package snmp;


import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.util.Map;
import java.util.Scanner;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import net.percederberg.mibble.Mib;
import net.percederberg.mibble.MibLoader;
import net.percederberg.mibble.MibLoaderException;
import net.percederberg.mibble.MibValueSymbol;
import net.percederberg.mibble.value.ObjectIdentifierValue;

import org.dsa.iot.dslink.node.Node;
import org.dsa.iot.dslink.node.Permission;
import org.dsa.iot.dslink.node.actions.Action;
import org.dsa.iot.dslink.node.actions.ActionResult;
import org.dsa.iot.dslink.node.actions.EditorType;
import org.dsa.iot.dslink.node.actions.Parameter;
import org.dsa.iot.dslink.node.value.Value;
import org.dsa.iot.dslink.node.value.ValueType;
import org.dsa.iot.dslink.serializer.Deserializer;
import org.dsa.iot.dslink.serializer.Serializer;
import org.dsa.iot.dslink.util.Objects;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.snmp4j.CommandResponder;
import org.snmp4j.CommandResponderEvent;
import org.snmp4j.MessageDispatcher;
import org.snmp4j.PDU;
import org.snmp4j.Snmp;
import org.snmp4j.TransportMapping;
import org.snmp4j.mp.MPv1;
import org.snmp4j.mp.MPv2c;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.SecurityProtocols;
import org.snmp4j.security.USM;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.GenericAddress;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.UdpAddress;
import org.snmp4j.smi.VariableBinding;
import org.snmp4j.transport.DefaultUdpTransportMapping;
import org.vertx.java.core.Handler;
import org.vertx.java.core.json.JsonArray;
import org.vertx.java.core.json.JsonObject;


public class SnmpLink {
	
	private final static Logger LOGGER;
	private Node node;
	private Node mibnode;
	Snmp snmp;
	private final Map<Node, ScheduledFuture<?>> futures;
	private MibLoader mibLoader;
	Serializer copySerializer;
	Deserializer copyDeserializer;
	private static final File MIB_STORE = new File(".mib_store");
	
	private SnmpLink(Node node, Serializer ser, Deserializer deser) {
		this.node = node;
		this.mibnode = node.createChild("MIBs").build();
		this.mibnode.setSerializable(false);
		this.copySerializer = ser;
		this.copyDeserializer = deser;
		this.futures = new ConcurrentHashMap<>();
	}
	
	public static void start(Node parent, Serializer copyser, Deserializer copydeser) {
		Node node = parent;
		final SnmpLink link = new SnmpLink(node, copyser, copydeser);
		link.init();
	}
	
	static {
        LOGGER = LoggerFactory.getLogger(SnmpLink.class);
    }
	
	private void init() {
		
		mibLoader = new MibLoader();
		if (!MIB_STORE.exists()) {
			if (!MIB_STORE.mkdirs()) LOGGER.error("error making Mib Store directory");
		}
		mibLoader.addDir(MIB_STORE);
		loadAllMibs();
		
		Address listenAddress = GenericAddress.parse(System.getProperty("snmp4j.listenAddress","udp:0.0.0.0/162"));
		TransportMapping<UdpAddress> transport;
		TransportMapping<UdpAddress> traptransport;
		
		try {
			transport = new DefaultUdpTransportMapping();
			if (listenAddress instanceof UdpAddress) {
				traptransport = new DefaultUdpTransportMapping((UdpAddress)listenAddress);
			} else {
				traptransport = new DefaultUdpTransportMapping();
			}
			snmp = new Snmp(transport);
			Snmp trapsnmp = new Snmp(traptransport);
			SecurityProtocols.getInstance().addDefaultProtocols();
			MessageDispatcher disp = snmp.getMessageDispatcher();
			disp.addMessageProcessingModel(new MPv1());
			disp.addMessageProcessingModel(new MPv2c());
			OctetString localEngineID = new OctetString(MPv3.createLocalEngineID());
			    // For command generators, you may use the following code to avoid
			    // engine ID clashes:
			    // MPv3.createLocalEngineID(
			    //   new OctetString("MyUniqueID"+System.currentTimeMillis())));
			USM usm = new USM(SecurityProtocols.getInstance(), localEngineID, 0);
			disp.addMessageProcessingModel(new MPv3(usm));
			
			CommandResponder trapListener = new CommandResponder() {
			     public synchronized void processPdu(CommandResponderEvent e) {
			    	 PDU command = e.getPDU();
			    	 if (command != null) {
			    		 LOGGER.debug("recieved trap: " + command.toString());
			    		 String from = ((UdpAddress) e.getPeerAddress()).getInetAddress().getHostAddress();
				    	 for (Node child: node.getChildren().values()) {
				    		 Value ip = child.getAttribute("ip");
				    		 if (ip != null && from.equals(ip.getString().split("/")[0])) {
				    			 Node tnode = child.getChild("TRAPS");
				    			 JsonArray traparr = new JsonArray(tnode.getValue().getString());
				    			 JsonObject jo = new JsonObject();
				    			 for (VariableBinding vb: command.toArray()) {
				    				 String fieldname = parseOid(vb.getOid());
				    				 jo.putString(fieldname, vb.toValueString());
				    			 }
				    			 traparr.addObject(jo);
				    			 tnode.setValue(new Value(traparr.toString()));
				    		 }
				    	 }
			    	 }
			    	 e.setProcessed(true);
			     }
			   };
			   
			   trapsnmp.addCommandResponder(trapListener);
			   trapsnmp.listen();
			   
			   snmp.listen();
			   LOGGER.debug("snmp started listening");
			   
		} catch (IOException e) {
			// TODO Auto-generated catch block
			LOGGER.debug("error:", e);
			//e.printStackTrace();
		}
		
		restoreLastSession();
		
		Action act = new Action(Permission.READ, new AddAgentHandler());
		act.addParameter(new Parameter("Name", ValueType.STRING));
		act.addParameter(new Parameter("IP", ValueType.STRING));
		act.addParameter(new Parameter("Port", ValueType.STRING, new Value(161)));
		act.addParameter(new Parameter("Polling Interval", ValueType.NUMBER, new Value(5)));
		act.addParameter(new Parameter("SNMP Version", ValueType.makeEnum("1", "2c", "3")));
		act.addParameter(new Parameter("Community String", ValueType.STRING, new Value("public")));
		act.addParameter(new Parameter("Security Name", ValueType.STRING, new Value("")));
		act.addParameter(new Parameter("Auth Protocol", ValueType.makeEnum("NONE", "MD5", "SHA")));
		act.addParameter(new Parameter("Auth Passphrase", ValueType.STRING, new Value("")));
		act.addParameter(new Parameter("Priv Protocol", ValueType.makeEnum("NONE", "DES", "AES128", "AES192", "AES256")));
		act.addParameter(new Parameter("Priv Passphrase", ValueType.STRING, new Value("")));
		act.addParameter(new Parameter("Engine ID", ValueType.STRING, new Value("")));
		act.addParameter(new Parameter("Context Engine", ValueType.STRING, new Value("")));
		act.addParameter(new Parameter("Context Name", ValueType.STRING, new Value("")));
		act.addParameter(new Parameter("Retries", ValueType.NUMBER, new Value(2)));
		act.addParameter(new Parameter("Timeout", ValueType.NUMBER, new Value(1500)));
		node.createChild("addAgent").setAction(act).build().setSerializable(false);
		act = new Action(Permission.READ, new AddMibHandler());
		Parameter param = new Parameter("MIB Text", ValueType.STRING);
		param.setEditorType(EditorType.TEXT_AREA);
		act.addParameter(param);
		mibnode.createChild("add MIB").setAction(act).build().setSerializable(false);
		
	}
	
	private void restoreLastSession() {
		if (node.getChildren() == null) return;
		for (Node child: node.getChildren().values()) {
			Value ip = child.getAttribute("IP");
			Value interval = child.getAttribute("Polling Interval");
			Value comStr = child.getAttribute("Community String");
			Value version = child.getAttribute("SNMP Version");
			Value secName = child.getAttribute("Security Name");
			Value authProt = child.getAttribute("Auth Protocol");
			Value authPass = child.getAttribute("Auth Passphrase");
			Value privProt = child.getAttribute("Priv Protocol");
			Value privPass = child.getAttribute("Priv Passphrase");
			Value engine = child.getAttribute("Engine ID");
			Value cEngine = child.getAttribute("Context Engine");
			Value cName = child.getAttribute("Context Name");
			Value retries = child.getAttribute("Retries");
			Value timeout = child.getAttribute("Timeout");
			if (ip!=null && interval!=null && comStr!=null && retries!=null && 
					timeout!=null && version!=null && secName!=null && authProt!=null
					&& authPass!=null && privProt!=null && privPass!=null && 
					engine!=null && cEngine!=null && cName!=null) {

				AgentNode an = new AgentNode(this, child);
				an.restoreLastSession();
			} else if (child.getAction() == null && child.getName() != "MIBs") {
				node.removeChild(child);
			}
		}
	}
	
	String parseOid(OID oid) {
		String oidString = oid.toDottedString();
		MibValueSymbol bestmatch = null;
		for (Mib mib: mibLoader.getAllMibs()) {
			MibValueSymbol mvs = mib.getSymbolByOid(oidString);
			ObjectIdentifierValue mvsOid = getOidFromSymbol(mvs);
			if (mvsOid != null) {
				if (bestmatch == null || mvsOid.toString().length() > getOidFromSymbol(bestmatch).toString().length()) {
					bestmatch = mvs;
				}
			}
		}
		if (bestmatch == null) return oidString;
		String matchingOidString = getOidFromSymbol(bestmatch).toString().replace('.', ',');
		oidString = oidString.replace('.', ',');
		String retString = oidString.replaceFirst(matchingOidString, bestmatch.getName());
		return retString.replace(',', '.');
		
	}
	
	private static ObjectIdentifierValue getOidFromSymbol(MibValueSymbol mvs) {
		if (mvs != null && mvs.getValue() instanceof ObjectIdentifierValue) {
            return (ObjectIdentifierValue) mvs.getValue();
        }
		return null;
	}
	
	private class AddMibHandler implements Handler<ActionResult> {
		public void handle(ActionResult event) {
			String mibText = event.getParameter("MIB Text", ValueType.STRING).getString();
			String trimmedText = removeLeadingComments(mibText);
			if (trimmedText.isEmpty()) {
				LOGGER.error("MIB is nothing but comments");
				return;
			}
			String name = trimmedText.trim().split("\\s+")[0];
			File mibFile = new File(MIB_STORE, name);
			if (mibFile.exists()) {
				if (!mibFile.delete()) LOGGER.error("error deleting old MIB file");
			}
			saveMib(mibFile, mibText);
			Node child = mibnode.createChild(name).build();
			child.setSerializable(false);
			Action act = new Action(Permission.READ, new RemoveMibHandler(child));
			child.createChild("remove").setAction(act).build().setSerializable(false);
			try {
				mibLoader.load(mibFile);
			} catch (IOException e) {
				LOGGER.error("IOException while loading MIB");
				LOGGER.debug("error:", e);
				//e.printStackTrace();
			} catch (MibLoaderException e) {
				LOGGER.error("MibLoaderException while loading MIB");
				LOGGER.debug("error:", e);
				//e.printStackTrace();
			}
		}
	}
	
	private String removeLeadingComments(String mibText) {
		while (!mibText.isEmpty()) {
			Scanner scan = new Scanner(mibText);
			String firstLine = scan.nextLine();
			scan.close();
			mibText = mibText.substring(firstLine.length()+1);
			firstLine = firstLine.trim();
			while (!firstLine.isEmpty()) {
				if (!firstLine.startsWith("--")) {
					return firstLine + "\n" + mibText;
				}
				String[] splitln = firstLine.substring(2).split("--", 2);
				if (splitln.length > 1) {
					firstLine = splitln[1];
				} else {
					firstLine = ""; 
				}
				firstLine = firstLine.trim();
			}			
		}
		return "";
	}
	
	private class RemoveMibHandler implements Handler<ActionResult> {
		private Node toRemove;
		RemoveMibHandler(Node remnode) {
			toRemove = remnode;
		}
		public void handle(ActionResult event) {
			String name = toRemove.getName();
			File remfile = new File(MIB_STORE, name);
			try {
				mibLoader.unload(remfile);
			} catch (MibLoaderException e) {
				// TODO Auto-generated catch block
				//e.printStackTrace();
				LOGGER.debug("error:", e);
			}
			if (!remfile.delete()) LOGGER.error("Error deleting MIB file");
			mibnode.removeChild(toRemove);
			
		}
	}
	
	private void saveMib(File mibFile, String mibText) {
		Writer writer = null;
		try {
		    writer = new OutputStreamWriter( new FileOutputStream(mibFile), "US-ASCII");
		    writer.write(mibText);
		} catch ( IOException e) {
		} finally {
		    try {
		        if ( writer != null)
		        writer.close( );
		    } catch ( IOException e) {
		    }
		}
	}
	
	private void loadAllMibs() {
		for (String mibName: Config.STANDARD_MIBS) {
			try {
				mibLoader.load(mibName);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				//e.printStackTrace();
				LOGGER.debug("error:", e);
			} catch (MibLoaderException e) {
				// TODO Auto-generated catch block
				//e.printStackTrace();
				LOGGER.debug("error:", e);
			}
		}
		for (File mibFile: MIB_STORE.listFiles()) {
			String name = mibFile.getName();
			Node child = mibnode.createChild(name).build();
			child.setSerializable(false);
			Action act = new Action(Permission.READ, new RemoveMibHandler(child));
			child.createChild("remove").setAction(act).build().setSerializable(false);
			try {
				mibLoader.load(mibFile);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				//e.printStackTrace();
				LOGGER.debug("error:", e);
			} catch (MibLoaderException e) {
				// TODO Auto-generated catch block
				//e.printStackTrace();
				LOGGER.debug("error:", e);
			}
		}
	}
	
	private class AddAgentHandler implements Handler<ActionResult> {
		public void handle(ActionResult event) {
			String comStr="N/A", secName="N/A", authProt="N/A", authPass="N/A",
					privProt="N/A", privPass="N/A", engine="N/A", cEngine="N/A", cName="N/A";
			String ip = event.getParameter("IP", ValueType.STRING).getString() + "/" 
					+ event.getParameter("Port", ValueType.STRING).getString();
			String name = event.getParameter("Name", ValueType.STRING).getString();
			long interval = (long) (1000*event.getParameter("Polling Interval", ValueType.NUMBER).getNumber().doubleValue());
			SnmpVersion version = SnmpVersion.parse(event.getParameter("SNMP Version").getString());
			if (version == null) version = SnmpVersion.v2c; 
			if (version != SnmpVersion.v3) {
				comStr = event.getParameter("Community String", ValueType.STRING).getString();
			} else {
				secName = event.getParameter("Security Name", ValueType.STRING).getString();
				authProt = event.getParameter("Auth Protocol").getString();
				authPass = event.getParameter("Auth Passphrase", ValueType.STRING).getString();
				privProt = event.getParameter("Priv Protocol").getString();
				privPass = event.getParameter("Priv Passphrase", ValueType.STRING).getString();
				engine = event.getParameter("Engine ID", ValueType.STRING).getString();
				cEngine = event.getParameter("Context Engine", ValueType.STRING).getString();
				cName = event.getParameter("Context Name", ValueType.STRING).getString();
			}
			int retries = event.getParameter("Retries", ValueType.NUMBER).getNumber().intValue();
			long timeout = event.getParameter("Timeout", ValueType.NUMBER).getNumber().longValue();
			
			Node child = node.createChild(name).build();
			child.setAttribute("Polling Interval", new Value(interval));
			child.setAttribute("ip", new Value(ip));
			child.setAttribute("Community String", new Value(comStr));
			child.setAttribute("SNMP Version", new Value(version.toString()));
			child.setAttribute("Security Name", new Value(secName));
			child.setAttribute("Auth Protocol", new Value(authProt));
			child.setAttribute("Auth Passphrase", new Value(authPass));
			child.setAttribute("Priv Protocol", new Value(privProt));
			child.setAttribute("Priv Passphrase", new Value(privPass));
			child.setAttribute("Engine ID", new Value(engine));
			child.setAttribute("Context Engine", new Value(cEngine));
			child.setAttribute("Context Name", new Value(cName));
			child.setAttribute("Retries", new Value(retries));
			child.setAttribute("Timeout", new Value(timeout));
			new AgentNode(getMe(), child);
		}
	}
	
	enum SnmpVersion {
		v1 ("1", SnmpConstants.version1), 
		v2c ("2c", SnmpConstants.version2c),
		v3 ("3", SnmpConstants.version3);
		private String str;
		private int vnum;
		private SnmpVersion(String str, int ver) {
			this.str = str;
			this.vnum = ver;
		}
		@Override
		public String toString() {
			return str;
		}
		public int getVersion() {
			return vnum;
		}
		public static SnmpVersion parse(String str) {
			for (SnmpVersion v: SnmpVersion.values()) {
				if (v.toString().equals(str)) return v;
			}
			return null;
		}
		}

	
    void setupOID(Node child, final AgentNode agent) {
        child.getListener().setOnSubscribeHandler(new Handler<Node>() {
            public void handle(final Node event) {
                if (futures.containsKey(event)) {
                    return;
                }
                ScheduledThreadPoolExecutor stpe = Objects.getDaemonThreadPool();
                ScheduledFuture<?> fut = stpe.scheduleWithFixedDelay(new Runnable() {
                    @Override
                    public void run() {
                    	if (event.getAttribute("oid") != null) agent.sendGetRequest(event);
                    }
                }, 0, agent.interval, TimeUnit.MILLISECONDS);
                futures.put(event, fut);
            }
        });

        child.getListener().setOnUnsubscribeHandler(new Handler<Node>() {
            @Override
            public void handle(Node event) {
                ScheduledFuture<?> fut = futures.remove(event);
                if (fut != null) {
                    fut.cancel(false);
                }
            }
        });
    }
	
	private SnmpLink getMe() {
		return this;
	}

}
