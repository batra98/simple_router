package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.MACAddress;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device {
  /** Routing table for the router */
  private RouteTable routeTable;

  /** ARP cache for the router */
  private ArpCache arpCache;

  /**
   * Creates a router for a specific host.
   * 
   * @param host hostname for the router
   */
  public Router(String host, DumpFile logfile) {
    super(host, logfile);
    this.routeTable = new RouteTable();
    this.arpCache = new ArpCache();
  }

  /**
   * @return routing table for the router
   */
  public RouteTable getRouteTable() {
    return this.routeTable;
  }

  /**
   * Load a new routing table from a file.
   * 
   * @param routeTableFile the name of the file containing the routing table
   */
  public void loadRouteTable(String routeTableFile) {
    if (!routeTable.load(routeTableFile, this)) {
      System.err.println("Error setting up routing table from file "
          + routeTableFile);
      System.exit(1);
    }

    System.out.println("Loaded static route table");
    System.out.println("-------------------------------------------------");
    System.out.print(this.routeTable.toString());
    System.out.println("-------------------------------------------------");
  }

  /**
   * Load a new ARP cache from a file.
   * 
   * @param arpCacheFile the name of the file containing the ARP cache
   */
  public void loadArpCache(String arpCacheFile) {
    if (!arpCache.load(arpCacheFile)) {
      System.err.println("Error setting up ARP cache from file "
          + arpCacheFile);
      System.exit(1);
    }

    System.out.println("Loaded static ARP cache");
    System.out.println("----------------------------------");
    System.out.print(this.arpCache.toString());
    System.out.println("----------------------------------");
  }

  /**
   * Handle an Ethernet packet received on a specific interface.
   * 
   * @param etherPacket the Ethernet packet that was received
   * @param inIface     the interface on which the packet was received
   */
  public void handlePacket(Ethernet etherPacket, Iface inIface) {
    System.out.println("*** -> Received packet: " +
        etherPacket.toString().replace("\n", "\n\t"));

    if (etherPacket.getEtherType() == Ethernet.TYPE_IPv4) {

      IPv4 header = (IPv4) etherPacket.getPayload();
      short chksm = header.getChecksum();
      header = header.setChecksum((short) 0);
      byte[] serialized = header.serialize();
      header = (IPv4) header.deserialize(serialized, 0, serialized.length);

      if (chksm == header.getChecksum()) {
        header = header.setTtl((byte) (header.getTtl() - 1));

        if (header.getTtl() > (byte) 0) {

          header = header.setChecksum((short) 0);
          serialized = header.serialize();
          header = (IPv4) header.deserialize(serialized, 0, serialized.length);
          Ethernet nep = (Ethernet) etherPacket.setPayload(header);

          for (Iface ifa : interfaces.values()) {
            if (ifa.getIpAddress() == header.getDestinationAddress()) {
              return; // Packet is for the router itself, drop it.
            }
          }

          RouteEntry re = routeTable.lookup(header.getDestinationAddress());

          if (re != null) {
            ArpEntry an = null;

            int nextHopIP = (re.getGatewayAddress() != 0) ? re.getGatewayAddress() : header.getDestinationAddress();
            an = arpCache.lookup(nextHopIP);

            if (an == null) {
              return;
            }

            MACAddress dstMac = an.getMac();
            MACAddress srcMac = re.getInterface().getMacAddress();
            nep = nep.setDestinationMACAddress(dstMac.toBytes());
            nep = nep.setSourceMACAddress(srcMac.toBytes());

            sendPacket(nep, re.getInterface());
          }
        }
      }
    }
  }
}
