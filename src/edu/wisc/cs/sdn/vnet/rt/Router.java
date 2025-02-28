package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.MACAddress;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.ICMP;
import net.floodlightcontroller.packet.Data;

import java.nio.ByteBuffer;

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

    // Ensure the packet is an IPv4 packet
    if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4) {
      return; // Drop non-IPv4 packets
    }

    // Extract IPv4 packet
    IPv4 ipPacket = (IPv4) etherPacket.getPayload();

    // Verify checksum
    short receivedChecksum = ipPacket.getChecksum();
    ipPacket.resetChecksum(); // Reset for correct computation
    ipPacket.serialize(); // Recalculate checksum
    if (receivedChecksum != ipPacket.getChecksum()) {
      return; // Drop packet if checksum is incorrect
    }

    // Decrement TTL
    byte ttl = ipPacket.getTtl();
    if (ttl <= 1) {
      return; // Drop packet if TTL expires
    }
    ipPacket.setTtl((byte) (ttl - 1));
    ipPacket.resetChecksum(); // Update checksum after modifying TTL

    // Check if packet is destined for the router itself
    int destIp = ipPacket.getDestinationAddress();
    for (Iface iface : this.interfaces.values()) {
      if (iface.getIpAddress() == destIp) {
        return; // Drop packet if it matches one of the router’s interfaces
      }
    }

    // Perform longest prefix match in the routing table
    RouteEntry bestRoute = this.routeTable.lookup(destIp);
    if (bestRoute == null) {
      return; // Drop packet if no route is found
    }

    // Determine next-hop IP
    int nextHopIp = bestRoute.getGatewayAddress();
    if (nextHopIp == 0) {
      nextHopIp = destIp; // If no gateway, the destination is directly reachable
    }

    // Find the outgoing interface
    Iface outIface = bestRoute.getInterface();
    if (outIface == null) {
      return; // Drop if no valid outgoing interface
    }

    // Lookup MAC address for the next hop in the ARP cache
    ArpEntry arpEntry = this.arpCache.lookup(nextHopIp);
    if (arpEntry == null) {
      return; // Drop packet if the MAC address is unknown
    }

    // Update Ethernet frame
    etherPacket.setSourceMACAddress(outIface.getMacAddress()); // Set source MAC to outgoing interface
    etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes()); // Set destination MAC

    // Forward the packet
    this.sendPacket(etherPacket, outIface);
  }
}
