using System;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using Newtonsoft.Json;
using PacketDotNet;
using SharpPcap;

namespace ConsolePacketSniffer
{
    class Program
    {
        static async Task Main(string[] args)
        {
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
            device.OnPacketArrival += async (sender, e) => await OnPacketArrival(e);
            device.Open(DeviceMode.Promiscuous, 1000);

            Console.WriteLine($"\nSniffing on: {device.Description}\nPress Enter to stop...\n");
            device.StartCapture();
            Console.ReadLine();
            device.StopCapture();
            device.Close();
        }

        private static async Task OnPacketArrival(CaptureEventArgs e)
        {
            try
            {
                var packet = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
                var ip = packet.Extract<IpPacket>();

                if (ip != null)
                {
                    string protocol = ip.Protocol.ToString();
                    string srcIp = ip.SourceAddress.ToString();
                    string dstIp = ip.DestinationAddress.ToString();

                    var udp = ip.Extract<UdpPacket>();
                    int? srcPort = udp?.SourcePort;
                    int? dstPort = udp?.DestinationPort;

                    string flag = DetectTrafficFlag(srcPort, dstPort);

                    string srcGeo = await GetGeoInfoAsync(srcIp);
                    string dstGeo = await GetGeoInfoAsync(dstIp);

                    Console.WriteLine($"\n[{DateTime.Now:HH:mm:ss}] {srcIp} ({srcGeo}) → {dstIp} ({dstGeo})");
                    Console.WriteLine($"  Protocol: {protocol} {flag}");
                    if (udp != null)
                        Console.WriteLine($"  Ports: {srcPort} → {dstPort}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
            }
        }

        private static async Task<string> GetGeoInfoAsync(string ip)
        {
            try
            {
                using var client = new HttpClient();
                var response = await client.GetAsync($"http://ip-api.com/json/{ip}");
                var json = await response.Content.ReadAsStringAsync();

                dynamic result = JsonConvert.DeserializeObject(json);
                if (result.status == "success")
                {
                    return $"{result.country}, {result.city} [{result.isp}]";
                }
            }
            catch { }

            return "Unknown Location";
        }

        private static string DetectTrafficFlag(int? srcPort, int? dstPort)
        {
            int[] xboxPorts = { 3074, 88, 500, 3544, 4500 };
            int[] psnPorts = { 3478, 3479, 3480 };

            if (xboxPorts.Contains(srcPort.GetValueOrDefault()) || xboxPorts.Contains(dstPort.GetValueOrDefault()))
                return "🔵 Xbox Live";
            if (psnPorts.Contains(srcPort.GetValueOrDefault()) || psnPorts.Contains(dstPort.GetValueOrDefault()))
                return "🔴 PlayStation Network";
            if (dstPort == 443 || dstPort == 80)
                return "🌐 Web/API";
            if (dstPort > 10000 && dstPort < 65535)
                return "🎮 Game/P2P";

            return "";
        }
    }
}
