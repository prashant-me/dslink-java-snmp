package snmp;


import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.util.Map;
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
import org.dsa.iot.dslink.node.actions.Parameter;
import org.dsa.iot.dslink.node.value.Value;
import org.dsa.iot.dslink.node.value.ValueType;
import org.dsa.iot.dslink.util.Objects;
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
	
	private Node node;
	Snmp snmp;
	private final Map<Node, ScheduledFuture<?>> futures;
	private MibLoader mibLoader;
	private static final File MIB_STORE = new File(System.getProperty("user.home"), ".mib_store");
	
	private SnmpLink(Node node) {
		this.node = node;
		this.futures = new ConcurrentHashMap<>();
	}
	
	public static void start(Node parent) {
		Node node = parent.createChild("SNMP").build();
		final SnmpLink link = new SnmpLink(node);
		link.init();
	}
	
	private void init() {
		
		mibLoader = new MibLoader();
		if (!MIB_STORE.exists()) {
			if (!MIB_STORE.mkdirs()) System.out.println("error making Mib Store directory");
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
			    		 System.out.println(command.toString());
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
			e.printStackTrace();
		}
		
		restoreLastSession();
		
		Action act = new Action(Permission.READ, new AddAgentHandler());
		act.addParameter(new Parameter("name", ValueType.STRING));
		act.addParameter(new Parameter("ip", ValueType.STRING));
		act.addParameter(new Parameter("port", ValueType.STRING));
		act.addParameter(new Parameter("refreshInterval", ValueType.NUMBER));
		node.createChild("addAgent").setAction(act).build().setSerializable(false);
		act = new Action(Permission.READ, new AddMibHandler());
		act.addParameter(new Parameter("MIB Text", ValueType.STRING));
		node.createChild("add MIB").setAction(act).build().setSerializable(false);
		
	}
	
	private void restoreLastSession() {
		if (node.getChildren() == null) return;
		for (Node child: node.getChildren().values()) {
			Value ip = child.getAttribute("ip");
			Value interval = child.getAttribute("interval");
			if (ip != null && interval != null) {
				AgentNode an = new AgentNode(this, child, ip.getString(), interval.getNumber().longValue());
				an.restoreLastSession();
			} else if (child.getAction() == null) {
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
			String name = mibText.trim().split("\\s+")[0];
			File mibFile = new File(MIB_STORE, name);
			if (mibFile.exists()) {
				if (!mibFile.delete()) System.out.println("error deleting old MIB file");
			}
			saveMib(mibFile, mibText);
			try {
				mibLoader.load(mibFile);
			} catch (IOException e) {
				System.out.println("IOException while loading MIB");
				e.printStackTrace();
			} catch (MibLoaderException e) {
				System.out.println("MibLoaderException while loading MIB");
				e.printStackTrace();
			}
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
				e.printStackTrace();
			} catch (MibLoaderException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		for (File mibFile: MIB_STORE.listFiles()) {
			try {
				mibLoader.load(mibFile);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (MibLoaderException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}
	
	private class AddAgentHandler implements Handler<ActionResult> {
		public void handle(ActionResult event) {
			String ip = event.getParameter("ip", ValueType.STRING).getString() + "/" 
					+ event.getParameter("port", ValueType.STRING).getString();
			String name = event.getParameter("name", ValueType.STRING).getString();
			long interval = event.getParameter("refreshInterval", ValueType.NUMBER).getNumber().longValue();
			Node child = node.createChild(name).build();
			new AgentNode(getMe(), child, ip, interval);
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
