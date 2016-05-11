using System;
using System.Net;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Threading.Tasks;
using System.Linq;
using System.Collections.Generic;

namespace NetworkInformation.SampleUsage
{
    public class Program
    {
        public static void Main(string[] args)
        {
            CommandLineTraceHandler.Enable();

            Dictionary<string, Action> options = new Dictionary<string, Action>()
            {
                { "interfaces", PrintNetworkInterfaces },
                { "interfaceproperties", PrintNetworkInterfaceProperties },
                { "interfacestatistics", PrintNetworkInterfaceStatistics },
                { "ipv4", PrintIpv4Statistics },
                { "ipv6", PrintIpv6Statistics },
                { "icmp4", PrintIcmp4Statistics },
                { "icmp6", PrintIcmp6Statistics },
                { "udp4", PrintUdp4Statistics },
                { "udp6", PrintUdp6Statistics },
                { "tcp4", PrintTcp4Statistics },
                { "tcp6", PrintTcp6Statistics },
                { "connections", PrintSocketConnections },
                { "networkchange", NetworkChangeTest },
                { "ipglobal", PrintIPGlobals }
            };

            string selection = (args?.Length >= 1) ? args[0] : null;
            if (selection == null || !options.Keys.Contains(selection))
            {
                Console.WriteLine("Options: " + Environment.NewLine + string.Join(Environment.NewLine, options.Keys.Select(s => $"* {s}")));
            }
            else
            {
                options[selection]();
            }
        }

        private static void PrintIPGlobals()
        {
            var globalProps = IPGlobalProperties.GetIPGlobalProperties();
            Console.WriteLine($"Domain Name: {globalProps.DomainName}");
            Console.WriteLine($"Host Name: {globalProps.HostName}");
            var addresses = globalProps.GetUnicastAddressesAsync().Result;
            Console.WriteLine($"Async result, UnicastAddresses [{addresses.Count}]");
            foreach (var addr in addresses)
            {
                Console.WriteLine("  * " + addr.Address.ToString());
                PrintProperties(addr, 6);
            }
        }

        private static void PrintNetworkInterfaceStatistics()
        {
            var interfaces = NetworkInterface.GetAllNetworkInterfaces();
            foreach (NetworkInterface iface in interfaces)
            {
                Console.WriteLine(iface.Name);
                PrintProperties(iface.GetIPStatistics());
            }
        }

        private static void PrintNetworkInterfaceProperties()
        {
            var interfaces = NetworkInterface.GetAllNetworkInterfaces();
            foreach (NetworkInterface iface in interfaces)
            {
                var props = iface.GetIPProperties();
                Console.WriteLine("Interface properties: " + iface.Name);
                PrintProperties(props);
                Console.WriteLine("--IPv4 Properties--");
                PrintProperties(props.GetIPv4Properties(), 4);
                Console.WriteLine("--IPv6 Properties--");
                PrintProperties(props.GetIPv6Properties(), 4);
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

        private static void PrintProperties(object obj, int indentLevel = 2)
        {
            foreach (PropertyInfo pi in obj.GetType().GetProperties().Where(pi => pi.GetIndexParameters().Length == 0)
                .Where(pi => pi.Name != "SyncRoot"))
            {
                try
                {
                    object retrieved = null;
                    string value;
                    try
                    {
                        retrieved = pi.GetValue(obj);
                        value = retrieved.ToString();
                    }
                    catch (TargetInvocationException tie)
                    {
                        value = tie.InnerException.GetType().Name;
                    }
                    catch (Exception e)
                    {
                        value = (new string(' ', indentLevel) + "**Encountered a non-TargetInvocationException**");
                        value += Environment.NewLine + e.ToString();
                    }

                    Console.WriteLine(new string(' ', indentLevel) + pi.Name + " = " + value);
                    if (retrieved is IEnumerable<object> && !(retrieved is IPAddressCollection) && !(retrieved is string) && !(retrieved is char[]))
                    {
                        Console.WriteLine(new string(' ', indentLevel) + $"[{Enumerable.Count((IEnumerable<object>)retrieved)} subvalues]");
                        foreach (var subVal in (IEnumerable<object>)retrieved)
                        {
                            Console.WriteLine(new string(' ', indentLevel) + "* " + subVal.ToString());
                            PrintProperties(subVal, indentLevel + 4);
                        }
                    }
                    else if (retrieved != null && retrieved.GetType() != typeof(object))
                    {
                        PrintProperties(retrieved, indentLevel + 2);
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine(new string(' ', indentLevel) + pi.Name + "::" + e.GetType().Name);
                }
            }
            foreach (MethodInfo mi in obj.GetType().GetMethods(BindingFlags.Instance | BindingFlags.Public)
                .Where(mi => mi.GetParameters().Length == 0 && !mi.Name.Contains("get_") && !mi.Name.Contains("set_")
                        && !mi.Name.Contains("ToString") && !mi.Name.Contains("GetHashCode") && !mi.Name.Contains("GetTypeCode")
                        && !mi.Name.Contains("ToCharArray") && mi.DeclaringType != typeof(string) && !mi.Name.Contains("Clone")
                        && !mi.Name.Contains("GetEnumerator") && !mi.Name.Contains("GetAddressBytes") && !mi.Name.Contains("MapToIP"))
                .Where(mi => mi.DeclaringType != typeof(object)))
            {
                try
                {
                    object retrieved = null;
                    string value;
                    try
                    {
                        retrieved = mi.Invoke(obj, null);
                        value = retrieved.ToString();
                    }
                    catch (TargetInvocationException tie)
                    {
                        value = tie.InnerException.GetType().Name;
                    }

                    Console.WriteLine(new string(' ', indentLevel) + mi.Name + "() = " + value);
                    if (retrieved is IEnumerable<object> && !(retrieved is IPAddressCollection) && !(retrieved is string))
                    {
                        Console.WriteLine(new string(' ', indentLevel) + $"[{Enumerable.Count((IEnumerable<object>)retrieved)} subvalues]");
                        foreach (var subVal in (IEnumerable<object>)retrieved)
                        {
                            Console.WriteLine(new string(' ', indentLevel) + "* " + subVal.ToString());
                            PrintProperties(subVal, indentLevel + 4);
                        }
                    }
                    else if (retrieved != null && retrieved.GetType() != typeof(object))
                    {
                        PrintProperties(retrieved, indentLevel + 2);
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine(new string(' ', indentLevel) + mi.Name + "::" + e.GetType().Name);
                }
            }
        }

        private static void PrintNetworkInterfaces()
        {
            var interfaces = NetworkInterface.GetAllNetworkInterfaces();
            foreach (var netInterface in interfaces)
            {
                Console.WriteLine("** Interface: " + netInterface.Name + " **");
                PrintProperties(netInterface);
            }
        }

        private static void NetworkChangeTest()
        {
            Console.WriteLine("Waiting for a Network Address or Connectivity change, press enter to continue...");
            NetworkChange.NetworkAddressChanged += OnNetworkAddressChanged;
            Console.Read();
            NetworkChange.NetworkAddressChanged -= OnNetworkAddressChanged;
            Console.WriteLine("No longer listening for changes. Press enter to exit.");
            Console.Read();
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

    // Doesn't work on Linux.
    public struct ColoredRegion : IDisposable
    {
        private ConsoleColor _previousColor;

        public static ColoredRegion Begin(ConsoleColor color)
        {
            ColoredRegion region;
            region._previousColor = Console.ForegroundColor;
            Console.ForegroundColor = color;
            return region;
        }

        public void Dispose()
        {
            Console.ForegroundColor = _previousColor;
        }
    }
}