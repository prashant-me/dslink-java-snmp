
#SNMP DSLink

A DSLink for Simple Network Management Protocol.

##License

GNU GPL

##Usage

After adding an Agent, you can create folders within its node, and add OIDs anywhere within its folder structure.
Adding an OID sends a GET request to the agent to get that OID's value. The dslink will continue to send GET requests
and update the OID's value regularly, every 'refreshInterval' seconds, as specified when adding an agent. After adding
an OID, you can call its 'set' action to send a SET request.
You can also invoke the 'walk' action from within an agent's folder structure. This will walk through the agent (Calling
GETNEXT repeatedly) and store the results in a folder.

The dslink will catch any traps sent to it and store them in 'TRAPS', under the 'SNMP' node

For walk results and incoming traps, the dslink will automatically parse OIDs into names using the standard IANA and 
IETF MIB files, as well as any user-defined MIB files. The 'MIBs' node displays all user-defined MIB files and allows
you to remove them. Invoke this node's 'add MIB' action with the full text of the MIB to add a new MIB file.

##Internals

Uses SNMP4J and Mibble java libraries.








