package edu.wisc.cs.sdn.vnet.sw;

import net.floodlightcontroller.packet.Ethernet;
import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import java.util.*;

/**
 * @author Aaron Gember-Jacobson
 */
public class Switch extends Device {
  private final Map<Integer, MacTableEntry> macTable;
  private final Timer timer;

  /**
   * Creates a switch for a specific host.
   * 
   * @param host    hostname for the switch
   * @param logfile DumpFile instance for logging
   */
  public Switch(String host, DumpFile logfile) {
    super(host, logfile);
    this.macTable = new HashMap<>();
    this.timer = new Timer(true);
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

    int sourceMAC = etherPacket.getSourceMAC().hashCode();
    int destMAC = etherPacket.getDestinationMAC().hashCode();

    // Learn the source MAC address
    if (!macTable.containsKey(sourceMAC) || macTable.get(sourceMAC).iface != inIface) {
      macTable.put(sourceMAC, new MacTableEntry(inIface));
      scheduleMACExpiration(sourceMAC);
    } else {
      macTable.get(sourceMAC).refresh();
    }

    // Forwarding decision
    if (macTable.containsKey(destMAC)) {
      // Known MAC: Forward to the correct interface
      Iface outIface = macTable.get(destMAC).iface;
      if (outIface != inIface) {
        sendPacket(etherPacket, outIface);
      }
    } else {
      // Unknown MAC: Flood the packet
      for (Iface iface : interfaces.values()) {
        if (!iface.equals(inIface)) {
          sendPacket(etherPacket, iface);
        }
      }
    }
  }

  /**
   * Schedules the expiration of a MAC address entry after 15 seconds.
   */
  private void scheduleMACExpiration(int macAddress) {
    timer.schedule(new TimerTask() {
      @Override
      public void run() {
        synchronized (macTable) {
          if (macTable.containsKey(macAddress) && macTable.get(macAddress).isExpired()) {
            macTable.remove(macAddress);
          }
        }
      }
    }, 15000);
  }

  /**
   * Inner class to store MAC table entries with a timeout mechanism.
   */
  private static class MacTableEntry {
    private Iface iface;
    private long lastUpdated;

    MacTableEntry(Iface iface) {
      this.iface = iface;
      refresh();
    }

    void refresh() {
      this.lastUpdated = System.currentTimeMillis();
    }

    boolean isExpired() {
      return (System.currentTimeMillis() - lastUpdated) > 15000;
    }
  }
}
