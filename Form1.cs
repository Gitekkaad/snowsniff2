using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using Whois.NET;


namespace SnowSniff2
{

    public partial class Form1 : Form
    {
        IPHostEntry myip;
        IPHostEntry daddr;
        Socket meinsocket;

        int i;
        int tcpoffset, dataoffset;
        string destaddr;
        string sorcaddr;
        string lastadress;

        StringBuilder zeile = new StringBuilder();

        string umaddr;
        public byte[] buf;


        int ipvers;
        int headlen;
        int sport;
        int dport;
        int ttl = 1;
        int proto;
        int flct;
        int count;
        int thcount;
        int retcount;



        public Form1()
        {
            InitializeComponent();

            this.FormClosing += Form1_FormClosing;

            _ = ssnifAsync();


        }

        private void Form1_FormClosing(Object sender, FormClosingEventArgs e)
        {

            System.Text.StringBuilder messageBoxCS = new System.Text.StringBuilder();
            messageBoxCS.AppendFormat("{0} = {1}", "CloseReason", e.CloseReason);
            messageBoxCS.AppendLine();
            messageBoxCS.AppendFormat("{0} = {1}", "Cancel", e.Cancel);
            messageBoxCS.AppendLine();
            MessageBox.Show(messageBoxCS.ToString(), "FormClosing Event");
        }





        public async Task ssnifAsync()

        {
            myip = Dns.GetHostEntry(Dns.GetHostName());
            for (i = 0; i < myip.AddressList.Length; i++)
            {
                if (myip.AddressList[i].AddressFamily ==
                AddressFamily.InterNetwork)
                    break;
            }

            if (i == myip.AddressList.Length) return;

            IPEndPoint endpunkt;

            endpunkt = new IPEndPoint(myip.AddressList[i], 0);

            //Socket meinsocket;

            meinsocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);

            meinsocket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);

            byte[] buf = new byte[meinsocket.ReceiveBufferSize];

            meinsocket.Bind(endpunkt);

            //meinsocket.IOControl(IOControlCode.NonBlockingIO, null, BitConverter.GetBytes(1));

            meinsocket.IOControl(IOControlCode.ReceiveAll, BitConverter.GetBytes(1), null);

           


            label3.Text = ("<--- analysing data for user string ");
            label3.Refresh();

        rms:

            await Task.Run(() => Lesen());

            textBox3.Text = thcount.ToString();
            textBox3.Refresh();


            flct++;
            textBox2.Text = (flct.ToString());
            textBox2.Refresh();

            textBox1.Text = count.ToString();
            textBox1.Refresh();

            if (count != 128) { goto rms; }

            richTextBox1.Update();
            richTextBox1.AppendText(zeile.ToString());
            richTextBox1.ScrollToCaret();

            QueryByIPAddress();

            goto rms;

        }


        public void QueryByIPAddress()
        {

            try
            {

                if (lastadress == sorcaddr)
                {


                    _ = textBox4.Text = retcount.ToString();

                    textBox4.Refresh();

                    retcount++;

                    return;
                }

                var result = WhoisClient.Query(sorcaddr);

                richTextBox2.Text = result.Raw.ToString();
                richTextBox2.Update();
                richTextBox2.ScrollToCaret();

                try
                {

                    label3.Text = result.OrganizationName.ToString();
                    label3.Update();
                    label3.Refresh();

                }

                catch (Exception e) { }


                if (Dns.GetHostEntry(sorcaddr.ToString()) != null)
                {

                    daddr = Dns.GetHostEntry(sorcaddr.ToString());
                    label5.Text = daddr.HostName;
                    label5.Refresh();

                }

            }



            catch (SocketException e)
            {

                label5.Text = "no dns entry for hostname";
                label5.Refresh();

            }

            lastadress = sorcaddr.ToString();
        }


        public void Lesen()

        {

            byte[] buf = new byte[meinsocket.ReceiveBufferSize];

            count = meinsocket.Receive(buf);

            thcount++;

            //if (count != 128) { return; }

            if (count != 128 && count != 136) { return; }

                destaddr = buf[16] + "." + buf[17] + "." + buf[18] + "." + buf[19];
            sorcaddr = buf[12] + "." + buf[13] + "." + buf[14] + "." + buf[15];

            umaddr = buf[12] + "." + buf[13] + "." + buf[14];
            //if (umaddr == "192.168.178") { goto rms; };

            if (umaddr == "192.168.178") { return; };

            tcpoffset = (buf[0] & 0x0f) * 4;
            dataoffset = (buf[tcpoffset + 12] >> 4) * 4;

            ipvers = (buf[0] >> 4);
            headlen = (buf[0] & 0x0f) * 4;
            sport = (buf[tcpoffset] << 8) + (buf[tcpoffset + 1]);
            dport = (buf[tcpoffset + 2] << 8) + (buf[tcpoffset + 3]);
            ttl = buf[8];
            proto = buf[9];

            DateTime myValue = DateTime.Now;
            zeile.Append(myValue.ToString());

            zeile.Append(" IPv ");
            zeile.Append(ipvers.ToString());

            //zeile.Append(" Hl ");
            //zeile.Append(headlen.ToString());

            zeile.Append(" : ");
            zeile.Append(sorcaddr.ToString());

            zeile.Append(" : ");
            zeile.Append(sport.ToString());

            zeile.Append(" : ");
            zeile.Append(destaddr.ToString());

            zeile.Append(" : ");
            zeile.Append(dport.ToString());

            zeile.Append("  TTL  ");
            zeile.Append(ttl.ToString());

            zeile.Append("  Protocol ");
            if (proto == 17) { zeile.Append(" UDP "); }
            if (proto == 6) { zeile.Append(" TCP "); }

            zeile.Append(" count -->> ");
            zeile.Append(count.ToString());
            zeile.Append(" username  ----->  ");

            // eavesdropper

            for (int b = (tcpoffset + dataoffset + 24); b < count; b++)
            {
                if (Char.IsControl(Convert.ToChar(buf[b])))
                    zeile.Append(".");
                else
                    zeile.Append(Convert.ToChar(buf[b]));
            }

            zeile.Append(" \r\n");



            




        }



    }






}





