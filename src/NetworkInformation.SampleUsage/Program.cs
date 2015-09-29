using System;
using System.Net;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Threading.Tasks;
using System.Linq;
using System.Diagnostics;

namespace NetworkInformation.SampleUsage
{
    public class Program
    {
        public static void Main(string[] args)
        {
            CommandLineTraceHandler.Enable();

            string selection = (args?.Length >= 1) ? args[0] : null;
            switch (selection)
            {
                case "networkinterfaces":
                    PrintNetworkInterfaces();
                    break;
                case "ipv4":
                    PrintIpv4Statistics();
                    break;
                case "ipv6":
                    PrintIpv6Statistics();
                    break;
                case "networkchange":
                    NetworkChangeTest();
                    break;
                case "icmp4":
                    PrintIcmp4Statistics();
                    break;
                case "icmp6":
                    PrintIcmp6Statistics();
                    break;
                case "udp4":
                    PrintUdp4Statistics();
                    break;
                case "udp6":
                    PrintUdp6Statistics();
                    break;
                case "tcp4":
                    PrintTcp4Statistics();
                    break;
                case "tcp6":
                    PrintTcp6Statistics();
                    break;
                case "connections":
                    PrintSocketConnections();
                    break;
                default:
                    Console.WriteLine("Invalid option.");
                    break;
            }
        }

        private static void PrintSocketConnections()
        {
            var activeTcpConnections = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections();
            Console.WriteLine("** Active TCP Connections **");
            foreach (var conn in activeTcpConnections)
            {
                Console.WriteLine($"ActiveTCP: Local:[{conn.LocalEndPoint}], Remote:[{conn.RemoteEndPoint}], State:{conn.State}");
            }

            var udpConnections = IPGlobalProperties.GetIPGlobalProperties().GetActiveUdpListeners();
            Console.WriteLine("** UDP Connections **");
            foreach (var conn in udpConnections)
            {
                Console.WriteLine($"UDP: {conn.AddressFamily}, [{conn.Address}], Port={conn.Port}");
            }

            var tcpConnections = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners();
            Console.WriteLine("** TCP Connections **");
            foreach (var conn in tcpConnections)
            {
                Console.WriteLine($"TCP: {conn.AddressFamily}, [{conn.Address}], Port={conn.Port}");
            }
        }

        private static void PrintTcp4Statistics()
        {
            TcpStatistics stats = IPGlobalProperties.GetIPGlobalProperties().GetTcpIPv4Statistics();
            Console.WriteLine("--TCPv4 Statistics--");
            PrintProperties(stats);
        }

        private static void PrintTcp6Statistics()
        {
            TcpStatistics stats = IPGlobalProperties.GetIPGlobalProperties().GetTcpIPv6Statistics();
            Console.WriteLine("--TCPv6 Statistics--");
            PrintProperties(stats);
        }

        private static void PrintUdp4Statistics()
        {
            UdpStatistics stats = IPGlobalProperties.GetIPGlobalProperties().GetUdpIPv4Statistics();
            Console.WriteLine("--UDPv4 Statistics--");
            PrintProperties(stats);
        }

        private static void PrintUdp6Statistics()
        {
            UdpStatistics stats = IPGlobalProperties.GetIPGlobalProperties().GetUdpIPv6Statistics();
            Console.WriteLine("--UDPv6 Statistics--");
            PrintProperties(stats);
        }

        private static void PrintIcmp4Statistics()
        {
            IcmpV4Statistics stats = IPGlobalProperties.GetIPGlobalProperties().GetIcmpV4Statistics();
            Console.WriteLine("--ICMPv4 Statistics--");
            PrintProperties(stats);
        }

        private static void PrintIcmp6Statistics()
        {
            IcmpV6Statistics stats = IPGlobalProperties.GetIPGlobalProperties().GetIcmpV6Statistics();
            Console.WriteLine("--ICMPv6 Statistics--");
            PrintProperties(stats);
        }

        private static void PrintIpv4Statistics()
        {
            IPGlobalStatistics stats = IPGlobalProperties.GetIPGlobalProperties().GetIPv4GlobalStatistics();
            Console.WriteLine("--IPv4 Statistics--");
            PrintProperties(stats);
        }

        private static void PrintIpv6Statistics()
        {
            IPGlobalStatistics stats = IPGlobalProperties.GetIPGlobalProperties().GetIPv6GlobalStatistics();
            Console.WriteLine("--IPv6 Statistics--");
            PrintProperties(stats);
        }

        private static void PrintProperties(object obj)
        {
            foreach (PropertyInfo pi in obj.GetType().GetProperties())
            {
                string value;
                try
                {
                    value = pi.GetValue(obj).ToString();
                }
                catch (TargetInvocationException tie)
                {
                    value = tie.InnerException.GetType().Name;
                }
                Console.WriteLine("  -> " + pi.Name + " = " + value);
            }
            foreach (MethodInfo mi in obj.GetType().GetMethods(BindingFlags.Instance | BindingFlags.Public)
                .Where(mi => mi.GetParameters().Length == 0 && !mi.Name.Contains("get_") && !mi.Name.Contains("set_"))
                .Where(mi => mi.DeclaringType != typeof(object)))
            {
                string value;
                try
                {
                    value = mi.Invoke(obj, null).ToString();
                }
                catch (TargetInvocationException tie)
                {
                    value = tie.InnerException.GetType().Name;
                }

                Console.WriteLine("  -> " + mi.Name + "() = " + value);
            }
        }

        private static void PrintNetworkInterfaces()
        {
            var interfaces = NetworkInterface.GetAllNetworkInterfaces();
            foreach (var netInterface in interfaces)
            {
                Console.WriteLine("Interface: " + netInterface.Name);
                PrintProperties(netInterface);
                Console.WriteLine(" >IP Statistics");
                PrintProperties(netInterface.GetIPStatistics());
            }
        }

        private static void NetworkChangeTest()
        {
            Console.WriteLine("Waiting for a Network Connectivity change, press any key to continue...");
            NetworkChange.NetworkAddressChanged += OnNetworkAddressChanged;
            Console.Read();
            NetworkChange.NetworkAddressChanged -= OnNetworkAddressChanged;
        }

        private static void OnNetworkAddressChanged(object sender, EventArgs e)
        {
            Console.WriteLine("Network Address Change Detected.");
        }

        private static string GetHostNameIfKnown(IPAddress address)
        {
            try
            {
                Task<IPHostEntry> t = Dns.GetHostEntryAsync(address);
                if (t.Wait(20))
                {
                    return t.Result.HostName;
                }
            }
            catch { }
            return address.ToString();
        }
    }
}