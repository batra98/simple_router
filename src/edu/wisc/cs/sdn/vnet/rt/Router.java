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

    // Step 1: Ensure the packet is an IPv4 packet
    if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4) {
      return; // Drop the packet if not IPv4
    }

    // Step 2: Extract IPv4 packet from Ethernet frame
    IPv4 ipPacket = (IPv4) etherPacket.getPayload();

    // Step 3: Verify IP checksum
    short receivedChecksum = ipPacket.getChecksum();
    ipPacket.resetChecksum(); // Reset checksum before recalculating
    byte[] serialized = ipPacket.serialize();
    short computedChecksum = (short) ((ByteBuffer.wrap(serialized).getShort(10)) & 0xFFFF);

    if (receivedChecksum != computedChecksum) {
      return; // Drop packet if checksum is invalid
    }

    // Step 4: Decrement TTL
    byte ttl = ipPacket.getTtl();
    ttl -= 1;
    if (ttl <= 0) {
      return; // Drop the packet if TTL expires
    }
    ipPacket.setTtl(ttl);
    ipPacket.resetChecksum(); // Reset checksum after modifying TTL

    // Step 5: Check if the packet is destined for the router itself
    int destIp = ipPacket.getDestinationAddress();
    for (Iface iface : this.interfaces.values()) {
      if (iface.getIpAddress() == destIp) {
        return; // Drop if the destination IP matches any router interface
      }
    }

    // Step 6: Find the appropriate route for forwarding
    RouteEntry bestRoute = this.routeTable.lookup(destIp);
    if (bestRoute == null) {
      return; // Drop packet if no route is found
    }

    // Step 7: Determine the next hop IP
    int nextHopIp = bestRoute.getGatewayAddress();
    if (nextHopIp == 0) {
      nextHopIp = destIp; // If no gateway, the destination is directly reachable
    }

    // Step 8: Get the outgoing interface
    Iface outIface = bestRoute.getInterface();
    if (outIface == null) {
      return; // Drop if no outgoing interface is found
    }

    // Step 9: Lookup the next hop MAC address using the ARP cache
    MACAddress nextHopMac = this.arpCache.lookup(nextHopIp);
    if (nextHopMac == null) {
      return; // Drop if the MAC address is unknown
    }

    // Step 10: Update Ethernet frame for forwarding
    etherPacket.setSourceMACAddress(outIface.getMacAddress());
    etherPacket.setDestinationMACAddress(nextHopMac.toBytes());

    // Step 11: Send the packet out
    this.sendPacket(etherPacket, outIface);
  }
}
