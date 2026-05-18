using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace PortScannerGUI
{
    public enum ScanMode
    {
        TCP,
        UDP,
        TCPAndUDP
    }

    public class ScanResult
    {
        public string Host { get; set; }
        public int Port { get; set; }
        public string Protocol { get; set; }
        public string Status { get; set; }
        public string Message { get; set; }
        public long ElapsedMs { get; set; }
        public string Worker { get; set; }
    }

    public class MainForm : Form
    {
        private TextBox txtHost;
        private NumericUpDown nudStartPort;
        private NumericUpDown nudEndPort;
        private NumericUpDown nudThreadCount;
        private NumericUpDown nudTimeout;
        private ComboBox cboProtocol;
        private Button btnStart;
        private Button btnStop;
        private Button btnRadius;
        private Button btnClear;
        private Button btnExport;
        private ProgressBar progressBar;
        private Label lblProgress;
        private ListView lvResults;
        private TextBox txtLog;

        private ConcurrentQueue<int> portQueue;
        private CancellationTokenSource scanCts;
        private int totalPorts;
        private int completedPorts;
        private int remainingWorkers;
        private int resultIndex;
        private string currentHost;
        private int currentTimeoutMs;
        private ScanMode currentMode;

        public MainForm()
        {
            Text = "多线程端口扫描器-LLB2023080904007-测试版";
            StartPosition = FormStartPosition.CenterScreen;
            Size = new Size(1120, 720);
            MinimumSize = new Size(1000, 620);

            BuildUi();
        }

        private void BuildUi()
        {
            Font = new Font("Microsoft YaHei UI", 9F, FontStyle.Regular, GraphicsUnit.Point);

            GroupBox groupInput = new GroupBox();
            groupInput.Text = "扫描参数";
            groupInput.Location = new Point(12, 10);
            groupInput.Size = new Size(1080, 92);
            groupInput.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            Controls.Add(groupInput);

            Label lblHost = new Label();
            lblHost.Text = "目标主机/IP：";
            lblHost.Location = new Point(14, 28);
            lblHost.AutoSize = true;
            groupInput.Controls.Add(lblHost);

            txtHost = new TextBox();
            txtHost.Location = new Point(92, 24);
            txtHost.Size = new Size(170, 24);
            txtHost.Text = "127.0.0.1";
            groupInput.Controls.Add(txtHost);

            Label lblStart = new Label();
            lblStart.Text = "起始端口：";
            lblStart.Location = new Point(280, 28);
            lblStart.AutoSize = true;
            groupInput.Controls.Add(lblStart);

            nudStartPort = new NumericUpDown();
            nudStartPort.Location = new Point(350, 24);
            nudStartPort.Minimum = 0;
            nudStartPort.Maximum = 65535;
            nudStartPort.Value = 1812;
            nudStartPort.Size = new Size(80, 24);
            groupInput.Controls.Add(nudStartPort);

            Label lblEnd = new Label();
            lblEnd.Text = "结束端口：";
            lblEnd.Location = new Point(448, 28);
            lblEnd.AutoSize = true;
            groupInput.Controls.Add(lblEnd);

            nudEndPort = new NumericUpDown();
            nudEndPort.Location = new Point(518, 24);
            nudEndPort.Minimum = 0;
            nudEndPort.Maximum = 65535;
            nudEndPort.Value = 1813;
            nudEndPort.Size = new Size(80, 24);
            groupInput.Controls.Add(nudEndPort);

            Label lblThread = new Label();
            lblThread.Text = "线程数：";
            lblThread.Location = new Point(616, 28);
            lblThread.AutoSize = true;
            groupInput.Controls.Add(lblThread);

            nudThreadCount = new NumericUpDown();
            nudThreadCount.Location = new Point(673, 24);
            nudThreadCount.Minimum = 2;
            nudThreadCount.Maximum = 3;
            nudThreadCount.Value = 3;
            nudThreadCount.Size = new Size(55, 24);
            groupInput.Controls.Add(nudThreadCount);

            Label lblTimeout = new Label();
            lblTimeout.Text = "超时(ms)：";
            lblTimeout.Location = new Point(745, 28);
            lblTimeout.AutoSize = true;
            groupInput.Controls.Add(lblTimeout);

            nudTimeout = new NumericUpDown();
            nudTimeout.Location = new Point(812, 24);
            nudTimeout.Minimum = 100;
            nudTimeout.Maximum = 10000;
            nudTimeout.Increment = 100;
            nudTimeout.Value = 1000;
            nudTimeout.Size = new Size(75, 24);
            groupInput.Controls.Add(nudTimeout);

            Label lblProtocol = new Label();
            lblProtocol.Text = "协议：";
            lblProtocol.Location = new Point(905, 28);
            lblProtocol.AutoSize = true;
            groupInput.Controls.Add(lblProtocol);

            cboProtocol = new ComboBox();
            cboProtocol.Location = new Point(950, 24);
            cboProtocol.Size = new Size(110, 24);
            cboProtocol.DropDownStyle = ComboBoxStyle.DropDownList;
            cboProtocol.Items.AddRange(new object[] { "TCP", "UDP", "TCP+UDP" });
            cboProtocol.SelectedIndex = 0;
            groupInput.Controls.Add(cboProtocol);

            btnRadius = new Button();
            btnRadius.Text = "Radius 1812/1813";
            btnRadius.Location = new Point(16, 58);
            btnRadius.Size = new Size(135, 26);
            btnRadius.Click += BtnRadius_Click;
            groupInput.Controls.Add(btnRadius);

            btnStart = new Button();
            btnStart.Text = "开始扫描";
            btnStart.Location = new Point(168, 58);
            btnStart.Size = new Size(95, 26);
            btnStart.Click += BtnStart_Click;
            groupInput.Controls.Add(btnStart);

            btnStop = new Button();
            btnStop.Text = "停止";
            btnStop.Location = new Point(278, 58);
            btnStop.Size = new Size(76, 26);
            btnStop.Enabled = false;
            btnStop.Click += BtnStop_Click;
            groupInput.Controls.Add(btnStop);

            btnClear = new Button();
            btnClear.Text = "清空结果";
            btnClear.Location = new Point(369, 58);
            btnClear.Size = new Size(90, 26);
            btnClear.Click += BtnClear_Click;
            groupInput.Controls.Add(btnClear);

            btnExport = new Button();
            btnExport.Text = "导出CSV";
            btnExport.Location = new Point(474, 58);
            btnExport.Size = new Size(90, 26);
            btnExport.Click += BtnExport_Click;
            groupInput.Controls.Add(btnExport);

            progressBar = new ProgressBar();
            progressBar.Location = new Point(580, 62);
            progressBar.Size = new Size(330, 18);
            progressBar.Minimum = 0;
            progressBar.Maximum = 100;
            groupInput.Controls.Add(progressBar);

            lblProgress = new Label();
            lblProgress.Text = "就绪";
            lblProgress.Location = new Point(920, 62);
            lblProgress.Size = new Size(140, 18);
            groupInput.Controls.Add(lblProgress);

            lvResults = new ListView();
            lvResults.Location = new Point(12, 112);
            lvResults.Size = new Size(1080, 400);
            lvResults.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
            lvResults.View = View.Details;
            lvResults.FullRowSelect = true;
            lvResults.GridLines = true;
            lvResults.Columns.Add("序号", 55, HorizontalAlignment.Left);
            lvResults.Columns.Add("主机", 135, HorizontalAlignment.Left);
            lvResults.Columns.Add("端口", 70, HorizontalAlignment.Left);
            lvResults.Columns.Add("协议", 70, HorizontalAlignment.Left);
            lvResults.Columns.Add("状态", 130, HorizontalAlignment.Left);
            lvResults.Columns.Add("说明", 410, HorizontalAlignment.Left);
            lvResults.Columns.Add("耗时(ms)", 80, HorizontalAlignment.Left);
            lvResults.Columns.Add("线程", 105, HorizontalAlignment.Left);
            Controls.Add(lvResults);

            Label lblLog = new Label();
            lblLog.Text = "运行日志：";
            lblLog.Location = new Point(12, 522);
            lblLog.AutoSize = true;
            lblLog.Anchor = AnchorStyles.Bottom | AnchorStyles.Left;
            Controls.Add(lblLog);

            txtLog = new TextBox();
            txtLog.Location = new Point(12, 545);
            txtLog.Size = new Size(1080, 125);
            txtLog.Anchor = AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
            txtLog.Multiline = true;
            txtLog.ScrollBars = ScrollBars.Vertical;
            txtLog.ReadOnly = true;
            Controls.Add(txtLog);

            AppendLog("程序启动。");
            AppendLog("PPT要求：图形界面、多线程2-3线程，并测试Radius 1812和1813端口。");
        }

        private void BtnRadius_Click(object sender, EventArgs e)
        {
            nudStartPort.Value = 1812;
            nudEndPort.Value = 1813;
            nudThreadCount.Value = 3;
            cboProtocol.SelectedIndex = 2; // TCP+UDP
            AppendLog("已设置为 Radius 测试端口：1812(Authentication) 和 1813(Accounting)。");
        }

        private void BtnStart_Click(object sender, EventArgs e)
        {
            string host = txtHost.Text.Trim();
            int startPort = (int)nudStartPort.Value;
            int endPort = (int)nudEndPort.Value;

            if (string.IsNullOrWhiteSpace(host))
            {
                MessageBox.Show("请输入目标主机或IP地址。", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            if (startPort > endPort)
            {
                MessageBox.Show("起始端口不能大于结束端口。", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            int count = endPort - startPort + 1;
            if (count > 2048)
            {
                DialogResult confirm = MessageBox.Show(
                    "端口数量较多，实验报告建议扫描小范围端口。仍然继续吗？",
                    "确认扫描范围",
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Question);

                if (confirm != DialogResult.Yes)
                    return;
            }

            currentHost = host;
            currentTimeoutMs = (int)nudTimeout.Value;
            currentMode = GetSelectedMode();

            lvResults.Items.Clear();
            progressBar.Value = 0;
            lblProgress.Text = "0/" + count;
            resultIndex = 0;
            completedPorts = 0;
            totalPorts = count;

            portQueue = new ConcurrentQueue<int>();
            for (int port = startPort; port <= endPort; port++)
                portQueue.Enqueue(port);

            scanCts = new CancellationTokenSource();

            SetUiScanning(true);
            AppendLog("开始扫描：" + currentHost + "，端口范围 " + startPort + "-" + endPort
                + "，协议 " + cboProtocol.SelectedItem + "，线程数 " + nudThreadCount.Value + "。");

            int workerCount = (int)nudThreadCount.Value;
            remainingWorkers = workerCount;
            for (int i = 1; i <= workerCount; i++)
            {
                string workerName = "ScanWorker-" + i;
                Thread worker = new Thread(() => WorkerLoop(workerName, scanCts.Token));
                worker.IsBackground = true;
                worker.Name = workerName;
                worker.Start();
                AppendLog("启动扫描线程：" + workerName);
            }
        }

        private void BtnStop_Click(object sender, EventArgs e)
        {
            if (scanCts != null)
            {
                scanCts.Cancel();
                AppendLog("已发送停止信号，正在等待正在超时的连接返回。");
            }
        }

        private void BtnClear_Click(object sender, EventArgs e)
        {
            if (btnStart.Enabled)
            {
                lvResults.Items.Clear();
                txtLog.Clear();
                progressBar.Value = 0;
                lblProgress.Text = "就绪";
                AppendLog("已清空结果。");
            }
        }

        private void BtnExport_Click(object sender, EventArgs e)
        {
            if (lvResults.Items.Count == 0)
            {
                MessageBox.Show("当前没有可导出的扫描结果。", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            using (SaveFileDialog dialog = new SaveFileDialog())
            {
                dialog.Filter = "CSV文件|*.csv";
                dialog.FileName = "port_scan_results.csv";
                if (dialog.ShowDialog() == DialogResult.OK)
                {
                    StringBuilder csv = new StringBuilder();
                    csv.AppendLine("Index,Host,Port,Protocol,Status,Message,ElapsedMs,Worker");
                    foreach (ListViewItem item in lvResults.Items)
                    {
                        string[] fields = new string[item.SubItems.Count];
                        for (int i = 0; i < item.SubItems.Count; i++)
                            fields[i] = EscapeCsv(item.SubItems[i].Text);
                        csv.AppendLine(string.Join(",", fields));
                    }

                    File.WriteAllText(dialog.FileName, csv.ToString(), new UTF8Encoding(true));
                    AppendLog("已导出CSV结果：" + dialog.FileName);
                }
            }
        }

        private string EscapeCsv(string value)
        {
            if (value == null)
                return "";
            bool needQuote = value.Contains(",") || value.Contains("\"") || value.Contains("\r") || value.Contains("\n");
            value = value.Replace("\"", "\"\"");
            return needQuote ? "\"" + value + "\"" : value;
        }

        private ScanMode GetSelectedMode()
        {
            if (cboProtocol.SelectedIndex == 1)
                return ScanMode.UDP;
            if (cboProtocol.SelectedIndex == 2)
                return ScanMode.TCPAndUDP;
            return ScanMode.TCP;
        }

        private void WorkerLoop(string workerName, CancellationToken token)
        {
            int port;
            while (!token.IsCancellationRequested && portQueue.TryDequeue(out port))
            {
                if (currentMode == ScanMode.TCP || currentMode == ScanMode.TCPAndUDP)
                {
                    ScanResult tcpResult = ScanTcp(currentHost, port, currentTimeoutMs, workerName);
                    AddResult(tcpResult);
                }

                if (!token.IsCancellationRequested && (currentMode == ScanMode.UDP || currentMode == ScanMode.TCPAndUDP))
                {
                    ScanResult udpResult = ScanUdp(currentHost, port, currentTimeoutMs, workerName);
                    AddResult(udpResult);
                }

                int done = Interlocked.Increment(ref completedPorts);
                UpdateProgress(done);
            }

            int left = Interlocked.Decrement(ref remainingWorkers);
            Ui(() => AppendLog(workerName + " 结束，剩余工作线程：" + left));

            if (left == 0)
            {
                Ui(() => FinishScan());
            }
        }

        private ScanResult ScanTcp(string host, int port, int timeoutMs, string workerName)
        {
            Stopwatch stopwatch = Stopwatch.StartNew();
            try
            {
                using (TcpClient client = new TcpClient())
                {
                    IAsyncResult ar = client.BeginConnect(host, port, null, null);
                    bool connected = ar.AsyncWaitHandle.WaitOne(timeoutMs);
                    stopwatch.Stop();

                    if (!connected)
                    {
                        try { client.Close(); } catch { }
                        return MakeResult(host, port, "TCP", "Filtered/Timeout",
                            "TCP connect超时，端口可能被过滤或主机无响应", stopwatch.ElapsedMilliseconds, workerName);
                    }

                    try
                    {
                        client.EndConnect(ar);
                        return MakeResult(host, port, "TCP", "Open",
                            "connect连接成功，TCP端口开放", stopwatch.ElapsedMilliseconds, workerName);
                    }
                    catch (SocketException ex)
                    {
                        return MakeResult(host, port, "TCP", "Closed",
                            "connect失败：" + ex.SocketErrorCode, stopwatch.ElapsedMilliseconds, workerName);
                    }
                }
            }
            catch (Exception ex)
            {
                stopwatch.Stop();
                return MakeResult(host, port, "TCP", "Closed/Error",
                    ex.GetType().Name + "：" + ex.Message, stopwatch.ElapsedMilliseconds, workerName);
            }
        }

        private ScanResult ScanUdp(string host, int port, int timeoutMs, string workerName)
        {
            Stopwatch stopwatch = Stopwatch.StartNew();

            try
            {
                using (UdpClient udp = new UdpClient())
                {
                    udp.Client.ReceiveTimeout = timeoutMs;
                    udp.Connect(host, port);

                    byte[] probe = Encoding.ASCII.GetBytes("RADIUS-PROBE");
                    udp.Send(probe, probe.Length);

                    try
                    {
                        IPEndPoint remote = null;
                        byte[] reply = udp.Receive(ref remote);
                        stopwatch.Stop();

                        string text = Encoding.ASCII.GetString(reply).Replace("\r", " ").Replace("\n", " ").Trim();
                        if (text.Length > 60)
                            text = text.Substring(0, 60) + "...";

                        return MakeResult(host, port, "UDP", "Open",
                            "收到UDP响应：" + text, stopwatch.ElapsedMilliseconds, workerName);
                    }
                    catch (SocketException ex)
                    {
                        stopwatch.Stop();

                        if (ex.SocketErrorCode == SocketError.TimedOut)
                        {
                            return MakeResult(host, port, "UDP", "Open|Filtered",
                                "UDP无响应：可能开放但未回包，也可能被防火墙过滤", stopwatch.ElapsedMilliseconds, workerName);
                        }

                        if (ex.SocketErrorCode == SocketError.ConnectionReset)
                        {
                            return MakeResult(host, port, "UDP", "Closed",
                                "收到ICMP端口不可达/连接重置", stopwatch.ElapsedMilliseconds, workerName);
                        }

                        return MakeResult(host, port, "UDP", "Unknown",
                            "UDP异常：" + ex.SocketErrorCode, stopwatch.ElapsedMilliseconds, workerName);
                    }
                }
            }
            catch (Exception ex)
            {
                stopwatch.Stop();
                return MakeResult(host, port, "UDP", "Closed/Error",
                    ex.GetType().Name + "：" + ex.Message, stopwatch.ElapsedMilliseconds, workerName);
            }
        }

        private ScanResult MakeResult(string host, int port, string protocol, string status, string message, long elapsedMs, string workerName)
        {
            return new ScanResult
            {
                Host = host,
                Port = port,
                Protocol = protocol,
                Status = status,
                Message = message,
                ElapsedMs = elapsedMs,
                Worker = workerName
            };
        }

        private void AddResult(ScanResult result)
        {
            Ui(() =>
            {
                int index = Interlocked.Increment(ref resultIndex);
                ListViewItem item = new ListViewItem(index.ToString());
                item.SubItems.Add(result.Host);
                item.SubItems.Add(result.Port.ToString());
                item.SubItems.Add(result.Protocol);
                item.SubItems.Add(result.Status);
                item.SubItems.Add(result.Message);
                item.SubItems.Add(result.ElapsedMs.ToString());
                item.SubItems.Add(result.Worker);

                if (result.Status.StartsWith("Open"))
                    item.ForeColor = Color.DarkGreen;
                else if (result.Status.StartsWith("Closed"))
                    item.ForeColor = Color.Firebrick;
                else
                    item.ForeColor = Color.DarkOrange;

                lvResults.Items.Add(item);
                lvResults.EnsureVisible(lvResults.Items.Count - 1);
            });
        }

        private void UpdateProgress(int done)
        {
            Ui(() =>
            {
                if (totalPorts <= 0)
                    return;

                int percent = (int)Math.Round(done * 100.0 / totalPorts);
                if (percent < 0) percent = 0;
                if (percent > 100) percent = 100;
                progressBar.Value = percent;
                lblProgress.Text = done + "/" + totalPorts + " (" + percent + "%)";
            });
        }

        private void FinishScan()
        {
            SetUiScanning(false);
            if (scanCts != null && scanCts.IsCancellationRequested)
                AppendLog("扫描已停止。");
            else
                AppendLog("扫描完成。共输出结果行：" + lvResults.Items.Count + "。");

            scanCts = null;
        }

        private void SetUiScanning(bool scanning)
        {
            btnStart.Enabled = !scanning;
            btnStop.Enabled = scanning;
            btnRadius.Enabled = !scanning;
            btnClear.Enabled = !scanning;
            btnExport.Enabled = !scanning;
            txtHost.Enabled = !scanning;
            nudStartPort.Enabled = !scanning;
            nudEndPort.Enabled = !scanning;
            nudThreadCount.Enabled = !scanning;
            nudTimeout.Enabled = !scanning;
            cboProtocol.Enabled = !scanning;
        }

        private void AppendLog(string message)
        {
            txtLog.AppendText("[" + DateTime.Now.ToString("HH:mm:ss") + "] " + message + Environment.NewLine);
        }

        private void Ui(Action action)
        {
            if (IsDisposed || !IsHandleCreated)
                return;

            if (InvokeRequired)
                BeginInvoke(action);
            else
                action();
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            if (scanCts != null)
                scanCts.Cancel();
            base.OnFormClosing(e);
        }
    }
}
