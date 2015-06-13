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
	private static final File MIB_STORE = new File(".mib_store");
	
	private SnmpLink(Node node) {
		this.node = node;
		this.mibnode = node.createChild("MIBs").build();
		this.mibnode.setSerializable(false);
		this.futures = new ConcurrentHashMap<>();
	}
	
	public static void start(Node parent) {
		Node node = parent.createChild("SNMP").build();
		final SnmpLink link = new SnmpLink(node);
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
		
		try {
			if (listenAddress instanceof UdpAddress) {
				transport = new DefaultUdpTransportMapping((UdpAddress)listenAddress);
			} else {
				transport = new DefaultUdpTransportMapping();
			}
			snmp = new Snmp(transport);
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
			   snmp.addCommandResponder(trapListener);
			   
			   snmp.listen();
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			LOGGER.debug("error:", e);
			//e.printStackTrace();
		}
		
		restoreLastSession();
		
		Action act = new Action(Permission.READ, new AddAgentHandler());
		act.addParameter(new Parameter("name", ValueType.STRING));
		act.addParameter(new Parameter("ip", ValueType.STRING));
		act.addParameter(new Parameter("port", ValueType.STRING, new Value(161)));
		act.addParameter(new Parameter("refreshInterval", ValueType.NUMBER));
		act.addParameter(new Parameter("communityString", ValueType.STRING, new Value("public")));
		act.addParameter(new Parameter("retries", ValueType.NUMBER, new Value(2)));
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
			Value ip = child.getAttribute("ip");
			Value interval = child.getAttribute("interval");
			Value comStr = child.getAttribute("communityString");
			Value retries = child.getAttribute("retries");
			Value timeout = child.getAttribute("timeout");
			if (ip != null && interval != null && comStr != null && retries != null && timeout != null) {
				AgentNode an = new AgentNode(this, child, ip.getString(),
						interval.getNumber().longValue(), comStr.getString(), 
						retries.getNumber().intValue(), timeout.getNumber().longValue());
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
			String ip = event.getParameter("ip", ValueType.STRING).getString() + "/" 
					+ event.getParameter("port", ValueType.STRING).getString();
			String name = event.getParameter("name", ValueType.STRING).getString();
			long interval = event.getParameter("refreshInterval", ValueType.NUMBER).getNumber().longValue();
			String comStr = event.getParameter("communityString", ValueType.STRING).getString();
			int retries = event.getParameter("retries", ValueType.NUMBER).getNumber().intValue();
			long timeout = event.getParameter("Timeout", ValueType.NUMBER).getNumber().longValue();
			Node child = node.createChild(name).build();
			new AgentNode(getMe(), child, ip, interval, comStr, retries, timeout);
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
                }, 0, agent.interval, TimeUnit.SECONDS);
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
