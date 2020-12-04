using PacketDotNet;
using SharpPcap;
using SharpPcap.Npcap;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

/*
 Reference:
 http://stackoverflow.com/questions/14114971/sending-my-own-arp-packet-using-sharppcap-and-packet-net
 https://www.codeproject.com/Articles/12458/SharpPcap-A-Packet-Capture-Framework-for-NET
*/

namespace CSArp
{
    public static class GetClientList
    {
        private static NpcapDevice capturedevice;
        private static Dictionary<IPAddress, PhysicalAddress> clientlist;
        private static readonly NpcapDeviceList capturedevicelist = NpcapDeviceList.Instance;

       
        

        /// <summary>
        /// Populates listview with machines connected to the LAN
        /// </summary>
        /// <param name="view"></param>
        /// <param name="interfacefriendlyname"></param>
        public static void GetAllClients(IView view, string interfacefriendlyname)
        {
            
           
            DebugOutputClass.Print(view, "Refresh client list");

            Initialize(view);


            capturedevicelist.Refresh(); //crucial for reflection of any network changes
            GetSelectedDevice(interfacefriendlyname, capturedevicelist);

            capturedevice.Open(DeviceMode.Promiscuous, 1000); //open device with 1000ms timeout
            IPAddress myipaddress = capturedevice.Addresses[1].Addr.ipAddress; //possible critical point : Addresses[1] in hardcoding the index for obtaining ipv4 address

            #region Sending ARP requests to probe for all possible IP addresses on LAN
            Task.Run(() => SendArpRequest(view, myipaddress));
            #endregion

            #region Retrieving ARP packets floating around and finding out the senders' IP and MACs

           Task.Run(()=> ScanNetwork(view, myipaddress));

            
            #endregion
        }

        private static void Initialize(IView view)
        {
            view.MainForm.Invoke(new Action(() => view.ToolStripStatusScan.Text = "Please wait..."));
            view.MainForm.Invoke(new Action(() => view.ToolStripProgressBarScan.Value = 0));
            if (capturedevice != null)
            {
                try
                {
                    capturedevice.StopCapture(); //stop previous capture
                    capturedevice.Close(); //close previous instances
                }
                catch (PcapException ex)
                {
                    DebugOutputClass.Print(view, "Exception at GetAllClients while trying to capturedevice.StopCapture() or capturedevice.Close() [" + ex.Message + "]");
                }
            }
            clientlist = new Dictionary<IPAddress, PhysicalAddress>(); //this is preventing redundant entries into listview and for counting total clients
            view.ListView1.Items.Clear();
            capturedevice = GetSelectedDevice(view.NetworkCardList.SelectedText, capturedevicelist);
            
        }

        private static void SendArpRequest(IView view, IPAddress myipaddress)
        {

            new Thread(() =>
            {
                try
                {
                    for (int ipindex = 1; ipindex <= 255; ipindex++)
                    {
                        ArpPacket arprequestpacket = new ArpPacket(ArpOperation.Request, PhysicalAddress.Parse("00-00-00-00-00-00"), IPAddress.Parse(GetRootIp(myipaddress) + ipindex), capturedevice.MacAddress, myipaddress);
                        EthernetPacket ethernetpacket = new EthernetPacket(capturedevice.MacAddress, PhysicalAddress.Parse("FF-FF-FF-FF-FF-FF"), EthernetType.Arp)
                        {
                            PayloadPacket = arprequestpacket
                        };
                        capturedevice.SendPacket(ethernetpacket);
                    }
                }
                catch (Exception ex)
                {
                    DebugOutputClass.Print(view, "Exception at GetClientList.GetAllClients() inside new Thread(()=>{}) while sending packets probably because old thread was still running while capturedevice was closed due to subsequent refresh [" + ex.Message + "]");
                }
            }).Start();
        }
        private static void ScanNetwork(IView view, IPAddress myipaddress)
        {

            
            capturedevice.Filter = "arp";
            RawCapture rawcapture = null;
            long scanduration = 5000;
            new Thread(() =>
            {


                try
                {
                    Stopwatch stopwatch = new Stopwatch();
                    stopwatch.Start();
                    while ((rawcapture = capturedevice.GetNextPacket()) != null && stopwatch.ElapsedMilliseconds <= scanduration)
                    {
                        Packet packet = Packet.ParsePacket(rawcapture.LinkLayerType, rawcapture.Data);
                        ArpPacket ArpPacket = packet.Extract<ArpPacket>();
                        if (!clientlist.ContainsKey(ArpPacket.SenderProtocolAddress) && ArpPacket.SenderProtocolAddress.ToString() != "0.0.0.0" && AreCompatibleIPs(ArpPacket.SenderProtocolAddress, myipaddress))
                        {
                            if (ArpPacket.SenderProtocolAddress.Equals(myipaddress))
                            {
                                continue;
                            }
                            clientlist.Add(ArpPacket.SenderProtocolAddress, ArpPacket.SenderHardwareAddress);
                            view.ListView1.Invoke(new Action(() =>
                            {
                               
                                view.ListView1.Items.Add(new ListViewItem(new string[] { clientlist.Count.ToString(), ArpPacket.SenderProtocolAddress.ToString(), GetMACString(ArpPacket.SenderHardwareAddress), "On", ApplicationSettingsClass.GetSavedClientNameFromMAC(GetMACString(ArpPacket.SenderHardwareAddress)) }));
                            }));
                            //Debug.Print("{0} @ {1}", ArpPacket.SenderProtocolAddress, ArpPacket.SenderHardwareAddress);
                        }
                        int percentageprogress = (int)((float)stopwatch.ElapsedMilliseconds / scanduration * 100);
                        view.MainForm.Invoke(new Action(() => view.ToolStripStatusScan.Text = "Scanning " + percentageprogress + "%"));
                        view.MainForm.Invoke(new Action(() => view.ToolStripProgressBarScan.Value = percentageprogress));
                        //Debug.Print(packet.ToString() + "\n");
                    }
                    stopwatch.Stop();
                    view.MainForm.Invoke(new Action(() => view.ToolStripStatusScan.Text = clientlist.Count.ToString() + " device(s) found"));
                    view.MainForm.Invoke(new Action(() => view.ToolStripProgressBarScan.Value = 100));
                    BackgroundScanStart(view); //start passive monitoring
                }
                catch (PcapException ex)
                {
                    DebugOutputClass.Print(view, "PcapException @ GetClientList.GetAllClients() @ new Thread(()=>{}) while retrieving packets [" + ex.Message + "]");
                    view.MainForm.Invoke(new Action(() => view.ToolStripStatusScan.Text = "Refresh for scan"));
                    view.MainForm.Invoke(new Action(() => view.ToolStripProgressBarScan.Value = 0));
                }
                catch (Exception ex)
                {
                    DebugOutputClass.Print(view, ex.Message);
                }

            }).Start();

            capturedevice.OnPacketArrival += (object sender, CaptureEventArgs e) =>
            {


                Packet packet = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
                ArpPacket ArpPacket = packet.Extract<ArpPacket>();//.Extract(typeof(ArpPacket));
                if (!clientlist.ContainsKey(ArpPacket.SenderProtocolAddress) && ArpPacket.SenderProtocolAddress.ToString() != myipaddress.ToString() && ArpPacket.SenderProtocolAddress.ToString() != "0.0.0.0" && AreCompatibleIPs(ArpPacket.SenderProtocolAddress, myipaddress))
                {
                    DebugOutputClass.Print(view, "Added " + ArpPacket.SenderProtocolAddress.ToString() + " @ " + GetMACString(ArpPacket.SenderHardwareAddress) + " from background scan!");
                    clientlist.Add(ArpPacket.SenderProtocolAddress, ArpPacket.SenderHardwareAddress);
                    view.ListView1.Invoke(new Action(() => view.ListView1.Items.Add(new ListViewItem(new string[] { (clientlist.Count).ToString(), ArpPacket.SenderProtocolAddress.ToString(), GetMACString(ArpPacket.SenderHardwareAddress), "On", ApplicationSettingsClass.GetSavedClientNameFromMAC(GetMACString(ArpPacket.SenderHardwareAddress)) }))));
                    view.MainForm.Invoke(new Action(() => view.ToolStripStatusScan.Text = clientlist.Count + " device(s) found"));
                }

            };


            capturedevice.StartCapture();
        }

        

        public static NpcapDevice GetSelectedDevice(string interfacefriendlyname, NpcapDeviceList capturedevicelist)
        {
            foreach (NpcapDevice item in capturedevicelist)
            {
                if (item.Interface.FriendlyName == null)
                {
                    continue;
                }

                if (item.Interface.FriendlyName.Equals(interfacefriendlyname))
                {
                    capturedevice = item;
                    break;
                }
            }
            return capturedevice;
        }

       

        /// <summary>
        /// Actively monitor ARP packets for signs of new clients after GetAllClients active scan is done
        /// </summary>
        public static void BackgroundScanStart(IView view)
        {
            try
            {
                IPAddress myipaddress = capturedevice.Addresses[1].Addr.ipAddress; //possible critical point : Addresses[1] in hardcoding the index for obtaining ipv4 address
                #region Sending ARP requests to probe for all possible IP addresses on LAN
                new Thread(() =>
                {
                    try
                    {
                        while (capturedevice != null)
                        {
                            for (int ipindex = 1; ipindex <= 255; ipindex++)
                            {
                                ArpPacket arprequestpacket = new ArpPacket(ArpOperation.Request, PhysicalAddress.Parse("00-00-00-00-00-00"), IPAddress.Parse(GetRootIp(myipaddress) + ipindex), capturedevice.MacAddress, myipaddress);
                                EthernetPacket ethernetpacket = new EthernetPacket(capturedevice.MacAddress, PhysicalAddress.Parse("FF-FF-FF-FF-FF-FF"), EthernetType.Arp)
                                {
                                    PayloadPacket = arprequestpacket
                                };
                                capturedevice.SendPacket(ethernetpacket);
                            }
                        }
                    }
                    catch (PcapException ex)
                    {
                        DebugOutputClass.Print(view, "PcapException @ GetClientList.BackgroundScanStart() probably due to capturedevice being closed by refreshing or by exiting application [" + ex.Message + "]");
                    }
                    catch (Exception ex)
                    {
                        DebugOutputClass.Print(view, "Exception at GetClientList.BackgroundScanStart() inside new Thread(()=>{}) while sending packets [" + ex.Message + "]");
                    }
                }).Start();
                #endregion

                #region Assign OnPacketArrival event handler and start capturing
                capturedevice.OnPacketArrival += (object sender, CaptureEventArgs e) =>
                {
                    Packet packet = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
                    ArpPacket ArpPacket = packet.Extract<ArpPacket>();//.Extract(typeof(ArpPacket));
                    if (!clientlist.ContainsKey(ArpPacket.SenderProtocolAddress) && ArpPacket.SenderProtocolAddress.ToString() != myipaddress.ToString() && ArpPacket.SenderProtocolAddress.ToString() != "0.0.0.0" && AreCompatibleIPs(ArpPacket.SenderProtocolAddress, myipaddress))
                    {
                        DebugOutputClass.Print(view, "Added " + ArpPacket.SenderProtocolAddress.ToString() + " @ " + GetMACString(ArpPacket.SenderHardwareAddress) + " from background scan!");
                        clientlist.Add(ArpPacket.SenderProtocolAddress, ArpPacket.SenderHardwareAddress);
                        view.ListView1.Invoke(new Action(() => view.ListView1.Items.Add(new ListViewItem(new string[] { (clientlist.Count).ToString(), ArpPacket.SenderProtocolAddress.ToString(), GetMACString(ArpPacket.SenderHardwareAddress), "On", ApplicationSettingsClass.GetSavedClientNameFromMAC(GetMACString(ArpPacket.SenderHardwareAddress)) }))));
                        view.MainForm.Invoke(new Action(() => view.ToolStripStatusScan.Text = clientlist.Count + " device(s) found"));
                    }
                };
                capturedevice.StartCapture();
                #endregion

            }
            catch (Exception ex)
            {
                DebugOutputClass.Print(view, "Exception at GetClientList.BackgroundScanStart() [" + ex.Message + "]");
            }

        }

        /// <summary>
        /// Stops any ongoing capture and closes capturedevice if open
        /// </summary>
        public static void CloseAllCaptures()
        {
            if (capturedevice != null)
            {
                capturedevice.StopCapture();
                capturedevice.Close();
            }


        }
        #region private
        /// <summary>
        /// Converts a PhysicalAddress to colon delimited string like FF:FF:FF:FF:FF:FF
        /// </summary>
        /// <param name="physicaladdress"></param>
        /// <returns></returns>
        private static string GetMACString(PhysicalAddress physicaladdress)
        {
            try
            {
                string retval = "";
                for (int i = 0; i <= 5; i++)
                    retval += physicaladdress.GetAddressBytes()[i].ToString("X2") + ":";
                return retval.Substring(0, retval.Length - 1);
            }
            catch (Exception ex)
            {
                throw ex;
            }

        }

        /// <summary>
        /// Converts say 192.168.1.4 to 192.168.1.
        /// </summary>
        /// <param name="ipaddress"></param>
        /// <returns></returns>
        private static string GetRootIp(IPAddress ipaddress)
        {
            string ipaddressstring = ipaddress.ToString();
            return ipaddressstring.Substring(0, ipaddressstring.LastIndexOf(".") + 1);
        }

        /// <summary>
        /// Checks if both IPAddresses have the same root ip
        /// </summary>
        /// <param name="ip1"></param>
        /// <param name="ip2"></param>
        /// <returns></returns>
        private static bool AreCompatibleIPs(IPAddress ip1, IPAddress ip2)
        {
            return (GetRootIp(ip1) == GetRootIp(ip2));
        }
        #endregion
    }
}
