using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace RadiusMockServer
{
    internal class Program
    {
        private static volatile bool running = true;

        private static void Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;
            Console.WriteLine("Radius 1812/1813 测试服务启动。");
            Console.WriteLine("作用：在本机打开 TCP/UDP 1812、1813，便于端口扫描程序截图验证。");
            Console.WriteLine("说明：这是实验辅助程序，不实现真正的 Radius 协议认证。");
            Console.WriteLine("按 Enter 键停止。");

            StartThread(() => TcpListenLoop(1812), "TCP-1812");
            StartThread(() => TcpListenLoop(1813), "TCP-1813");
            StartThread(() => UdpListenLoop(1812), "UDP-1812");
            StartThread(() => UdpListenLoop(1813), "UDP-1813");

            Console.ReadLine();
            running = false;
            Console.WriteLine("正在停止，请稍候...");
            Thread.Sleep(500);
        }

        private static void StartThread(ThreadStart start, string name)
        {
            Thread thread = new Thread(start);
            thread.IsBackground = true;
            thread.Name = name;
            thread.Start();
            Console.WriteLine("已启动监听线程：" + name);
        }

        private static void TcpListenLoop(int port)
        {
            TcpListener listener = null;
            try
            {
                listener = new TcpListener(IPAddress.Any, port);
                listener.Start();
                Console.WriteLine("TCP " + port + " 正在监听。");

                while (running)
                {
                    if (!listener.Pending())
                    {
                        Thread.Sleep(100);
                        continue;
                    }

                    using (TcpClient client = listener.AcceptTcpClient())
                    {
                        string remote = client.Client.RemoteEndPoint.ToString();
                        Console.WriteLine("TCP " + port + " 收到连接：" + remote);

                        byte[] data = Encoding.ASCII.GetBytes("RADIUS-MOCK-OK " + port + "\r\n");
                        client.GetStream().Write(data, 0, data.Length);
                    }
                }
            }
            catch (SocketException ex)
            {
                Console.WriteLine("TCP " + port + " 监听失败：" + ex.Message);
                Console.WriteLine("请检查端口是否已被占用，或是否需要关闭防火墙限制。");
            }
            finally
            {
                if (listener != null)
                    listener.Stop();
            }
        }

        private static void UdpListenLoop(int port)
        {
            UdpClient udp = null;
            try
            {
                udp = new UdpClient(port);
                Console.WriteLine("UDP " + port + " 正在监听。");

                while (running)
                {
                    if (udp.Available == 0)
                    {
                        Thread.Sleep(100);
                        continue;
                    }

                    IPEndPoint remote = new IPEndPoint(IPAddress.Any, 0);
                    byte[] request = udp.Receive(ref remote);
                    string text = Encoding.ASCII.GetString(request);
                    Console.WriteLine("UDP " + port + " 收到数据：" + remote + " -> " + text);

                    byte[] response = Encoding.ASCII.GetBytes("RADIUS-MOCK-OK " + port);
                    udp.Send(response, response.Length, remote);
                }
            }
            catch (SocketException ex)
            {
                Console.WriteLine("UDP " + port + " 监听失败：" + ex.Message);
                Console.WriteLine("请检查端口是否已被占用，或是否需要关闭防火墙限制。");
            }
            finally
            {
                if (udp != null)
                    udp.Close();
            }
        }
    }
}
