using PacketDotNet;
using SharpPcap;
using SharpPcap.Npcap;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;

namespace CSArp
{
    public static class ARPExtensions
    {

        private static readonly Dictionary<IPAddress, PhysicalAddress> clientList = new Dictionary<IPAddress, PhysicalAddress>();
        
        public static Dictionary<IPAddress, PhysicalAddress> Resolve(
            this ARP arp,
            NpcapDevice device,
            IPAddress destIP,
            IPAddress localIP,
            PhysicalAddress localMAC)
        {
            clientList.Clear();
            var request = BuildRequest(destIP, localMAC, localIP);
            string arpFilter = "arp and ether dst " + localMAC.ToString();

            device.Open(DeviceMode.Promiscuous, 20);
            device.Filter = arpFilter;
            var lastRequestTime = DateTime.FromBinary(0);
            var requestInterval = new TimeSpan(0, 0, 1);
            ArpPacket arpPacket = null;

            var timeoutDateTime = DateTime.Now + arp.Timeout;

            while (DateTime.Now < timeoutDateTime)
            {
                if (requestInterval<(DateTime.Now-lastRequestTime))
                {
                    device.SendPacket(request);
                    lastRequestTime = DateTime.Now;
                }

                var reply = device.GetNextPacket();
                if (reply == null)
                {
                    continue;
                }

                var packet = Packet.ParsePacket(reply.LinkLayerType, reply.Data);

                arpPacket = packet.Extract<ArpPacket>();

                if (arpPacket==null)
                {
                    continue;
                }

                if (arpPacket.SenderHardwareAddress.Equals(destIP))
                {
                    break;
                }
            }
            device.Close();

            if (DateTime.Now>=timeoutDateTime)
            {
               
                return null;
            }
            else
            {
                
                var key = arpPacket.SenderProtocolAddress;
                var value = arpPacket.SenderHardwareAddress;
                clientList.Add(key, value);
                return clientList;
            }
            
           
        }

        private static Packet BuildRequest(IPAddress destinationIP,PhysicalAddress localMac,IPAddress localIP)
        {
            var ethernetPacket = new EthernetPacket(localMac, PhysicalAddress.Parse("FF-FF-FF-FF-FF-FF"), EthernetType.Arp);
            var arpPacket = new ArpPacket(ArpOperation.Request, PhysicalAddress.Parse("00-00-00-00-00-00"), destinationIP, localMac, localIP);
            ethernetPacket.PayloadPacket = arpPacket;
            return ethernetPacket;
        }
    }
}
