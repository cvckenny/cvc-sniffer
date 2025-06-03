using System;
using PacketDotNet;
using SharpPcap;

namespace ConsolePacketSniffer
{
    class Program
    {
        static void Main(string[] args)
        {
            // Get a list of available devices
            var devices = CaptureDeviceList.Instance;

            if (devices.Count < 1)
            {
                Console.WriteLine("No network devices found. Ensure Npcap is installed.");
                return;
            }

            Console.WriteLine("Available devices:");
            for (int i = 0; i < devices.Count; i++)
            {
                Console.WriteLine($"{i}: {devices[i].Description}");
            }

            Console.Write("Select device number to sniff: ");
            if (!int.TryParse(Console.ReadLine(), out int deviceIndex) || deviceIndex < 0 || deviceIndex >= devices.Count)
            {
                Console.WriteLine("Invalid device index.");
                return;
            }

            var device = devices[deviceIndex];

            // Register packet event handler
            device.OnPacketArrival += new PacketArrivalEventHandler(OnPacketArrival);

            // Open the device for capturing
            device.Open(DeviceMode.Promiscuous, 1000);
            Console.WriteLine($"\nSniffing on: {device.Description}\nPress Enter to stop...\n");

            // Start the capture
            device.StartCapture();

            Console.ReadLine();

            // Stop and clean up
            device.StopCapture();
            device.Close();
        }

        private static void OnPacketArrival(object sender, CaptureEventArgs e)
        {
            try
            {
                var packet = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
                var ip = packet.Extract<PacketDotNet.IpPacket>();

                if (ip != null)
                {
                    Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] {ip.SourceAddress} → {ip.DestinationAddress} | Protocol: {ip.Protocol}");

                    // Filter for UDP (commonly used in console multiplayer)
                    if (ip.Protocol == System.Net.Sockets.ProtocolType.Udp)
                    {
                        var udp = ip.Extract<UdpPacket>();
                        if (udp != null)
                        {
                            Console.WriteLine($"  UDP SrcPort: {udp.SourcePort} → DstPort: {udp.DestinationPort}");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error parsing packet: " + ex.Message);
            }
        }
    }
}
