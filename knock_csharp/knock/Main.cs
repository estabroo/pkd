using System;
using System.Drawing;
using System.Windows.Forms;
using System.Collections;
using System.Security.Cryptography;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using System.Threading;

namespace knock
{
	class MainClass
	{
		public static void Main(string[] args)
		{
			Application.Run(new KnockUI());
		}
	}
	
	
	class KnockUI : Form
	{
		struct _host {
			public string name;
			public string host;
			public string key;
			public string tag;
		}
		
		private Button btnEdit;
		private Button btnRemove;
		private Button btnNew;
		private Button btnKnock;
		private Button btnExit;
		private ListView list;
		
		// stuff in new/edit dialog
		private Form      newEdit;
		private TextBox   editName;
		private TextBox   editTag;
		private TextBox   editHost;
		private TextBox   editKey;
		private bool      editIsNew;
		private Hashtable hostHash;
		
		// password dialog
		private Form passD;
		private TextBox passKey;
		private bool badPass;
		private SymmetricAlgorithm keeper;
		private byte [] IVB;
		private byte [] KEYB;
		
		private void btnExitClick(object sender, System.EventArgs e) {
			Application.Exit();
			System.Environment.Exit(0); // each form is it's own app?
		}
		
		private void btnKnockClick(object sender, System.EventArgs e) {
			
			foreach (ListViewItem item in list.SelectedItems) {
				if (hostHash.ContainsKey(item.Text)) {
					knock(item.Text);
				}
			}
		}
		
		private void btnNewClick(object sender, System.EventArgs e) {
			_host stuff;
			
			stuff.name = "";
			stuff.host = "";
			stuff.key = "";
			stuff.tag = "KN0C";
			
			editInfo(stuff, true);
		}
		
		private void btnEditClick(object sender, System.EventArgs e) {
			_host stuff;
			
			foreach (ListViewItem item in list.SelectedItems) {
				if (hostHash.ContainsKey(item.Text)) {
					stuff = (_host)hostHash[item.Text];
					editInfo(stuff, false);
				}
			}
		}
		
		private void btnRemoveClick(object sender, System.EventArgs e) {
			ArrayList stuffToRemove = new ArrayList();
			
			foreach (ListViewItem item in list.SelectedItems) {
				if (hostHash.ContainsKey(item.Text)) {
					hostHash.Remove(item.Text);
				}
				stuffToRemove.Add(item);
			}
			foreach (ListViewItem item in stuffToRemove) {
				list.Items.Remove(item);
			}
			
			_save_config();
		}
		
		public KnockUI() {
			/* label the window */
			this.Text = "IPT_PKD Knock";
			this.Font = new Font("Terminal Mono", (float)10.0);
			
			hostHash = new Hashtable();
			keeper = new RijndaelManaged();
			
			btnEdit = new System.Windows.Forms.Button();
			btnEdit.Location = new System.Drawing.Point(110,5);
			btnEdit.Text = "Edit";
			btnEdit.Click += btnEditClick;
			
			btnRemove = new System.Windows.Forms.Button();
			btnRemove.Location = new System.Drawing.Point(110, 30);
			btnRemove.Text = "Remove";
			btnRemove.Click += btnRemoveClick;
		
			btnNew = new System.Windows.Forms.Button();
			btnNew.Location = new System.Drawing.Point(110,55);
			btnNew.Text = "New";
			btnNew.Click += btnNewClick;
			
			btnKnock = new System.Windows.Forms.Button();
			btnKnock.Location = new System.Drawing.Point(110,80);
			btnKnock.Text = "Knock";
			btnKnock.Click += btnKnockClick;
			
			btnExit = new System.Windows.Forms.Button();
			btnExit.Location = new System.Drawing.Point(110,150);
			btnExit.Text = "Exit";
			btnExit.Click += btnExitClick;
			
			list = new System.Windows.Forms.ListView();
			list.Location = new System.Drawing.Point(5, 5);
			list.Size = new System.Drawing.Size(100, 170);
			list.View = View.List;
			list.Columns.Add("Location");
			list.FullRowSelect = true;
			list.Sorting = SortOrder.Ascending;
			list.Activation = ItemActivation.Standard;
			list.DoubleClick += btnKnockClick;
			list.Scrollable = true;
			
			for (badPass = true; badPass == true; ) {
				passwordDialog();
				_load_config();
				if (badPass == true) {
					Thread.Sleep(5000);
				}
			}
			
			this.AutoScaleBaseSize = new System.Drawing.Size(5, 10);
			//this.AutoScaleMode = AutoScaleMode.Font;
			this.ClientSize = new System.Drawing.Size(190, 180);
			this.Controls.Add(btnKnock);
			this.Controls.Add(btnEdit);
			this.Controls.Add(btnRemove);
			this.Controls.Add(btnNew);
			this.Controls.Add(btnExit);
			this.Controls.Add(list);
		}
		
		// converts given string to byte array of given size, zero fills to length
		private void stringTobyte(string s, byte [] b) {
			byte [] btmp;
			string  lower;
			byte    c;
			byte    v;
			int     i;
			int     j;
			
			System.Text.ASCIIEncoding encode = new System.Text.ASCIIEncoding();
			if (s.StartsWith("0x")) {
				lower = s.ToLower();
				j = 0;
				v = 0;
				for (i = 2; i < lower.Length && j < b.Length; i++) {
					c = (byte)(lower[i] >= 'a' ? ((int)lower[i] - (int)'a') + 10 : (int)lower[i] - (int)'0');
					if ((i % 2) == 0) {
						v = (byte)((int)c << 4);
					} else {
						v |= c;
						b[j++] = v;
					}
				}
				if (((i % 2) != 0) && (j < b.Length)) {
					b[j++] = v;
				}
				for (; j < b.Length; j++) {
					b[j] = 0;
				}
			} else {
				btmp = encode.GetBytes(s);
				for (i = 0; i < b.Length; i++) {
					if (i < btmp.Length) {
						b[i] = btmp[i];
					} else {
						b[i] = 0;
					}
				}
			}
			
		}
		
		private void knock(string host) {
			HashAlgorithm hash = new SHA256Managed();
			Random rand = new Random();
			byte [] bkey = new byte[40];
			byte [] btag = new byte[4];
			byte [] bport = new byte[4];
			byte [] randbits = new byte[12];
			short port = (short)rand.Next(1024, 30000);
			int i;
			int j;
			
			_host machine = (_host)hostHash[host];
			stringTobyte(machine.key, bkey);
			stringTobyte(machine.tag, btag);
			
			//bport = pack port upper, port lower, port upper, port lower
			bport[0] = (byte)((port & 0xff00) >> 8);
			bport[1] = (byte)(port & 0x00ff);
			bport[2] = (byte)((port & 0xff00) >> 8);
			bport[3] = (byte)(port & 0x00ff);
			
			DateTime dt = DateTime.UtcNow;
			DateTime epoch = new DateTime(1970, 1, 1, 0, 0, 1);
			long ticks = dt.Ticks - epoch.Ticks;
			long seconds = ticks/10000000;

			byte [] sb = System.BitConverter.GetBytes((uint)seconds);
			rand.NextBytes(randbits);
			
			//p = btag + (int)(timeinsecs), 0, randint, randint, randint
			byte [] p = new byte[btag.Length + sb.Length + 4 + randbits.Length];
			j = 0;
			for (i = 0; i < btag.Length; i++) {
				p[j++] = btag[i];
			}
			for (i = 0; i < sb.Length; i++) {
				p[j++] = sb[i];
			}
			for (i = 0; i < 4; i++) {
				p[j++] = 0;
			}
			for (i = 0; i < randbits.Length; i++) {
				p[j++] = randbits[i];
			}
			//ssum = bport + p + bkey
			byte [] ssum = new byte[bport.Length + p.Length + bkey.Length];
			i = 0;
			for (j = 0; j < bport.Length; j++) {
				ssum[i++] = bport[j];
			}
			for (j = 0; j < p.Length; j++) {
				ssum[i++] = p[j];
			}
			for (j = 0; j < bkey.Length; j++) {
				ssum[i++] = bkey[j];
			}
			byte [] d = hash.ComputeHash(ssum);
			
			// packet = p+d
			byte [] packet = new byte[p.Length + d.Length];
			i = 0;
			for (j = 0; j < p.Length; j++) {
				packet[i++] = p[j];
			}
			for (j = 0; j < d.Length; j++) {
				packet[i++] = d[j];
				d[j] = 0;
			}
			
			IPAddress ipAddress = ( Dns.GetHostEntry(machine.host) ).AddressList[0];
			IPEndPoint ipEndpoint = new IPEndPoint(ipAddress, port);
			
			Socket udpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
			udpSocket.SendTo(packet, ipEndpoint);
		}
		
		private void editCancelClick(object sender, System.EventArgs e) {
			newEdit.Close();
		}
		
		private void editSaveClick(object sender, System.EventArgs e) {
			_host server = new _host();
			
			server.name = editName.Text;
			server.host = editHost.Text;
			server.tag = editTag.Text;
			server.key = editKey.Text;
							
			if (hostHash.ContainsKey(server.name)) {
				hostHash.Remove(server.name);
			}
			hostHash.Add(server.name, server);
			
			if (editIsNew == true) {
				list.Items.Add(server.name);
			}

			newEdit.Close();
			
			_save_config();
		}
		
		private void editInfo(_host machine, bool isNew) {
			newEdit = new Form();
			newEdit.FormBorderStyle = FormBorderStyle.FixedDialog;
			newEdit.ControlBox = false;
			newEdit.MinimizeBox = false;
			newEdit.MaximizeBox = false;

			newEdit.AutoScaleMode = AutoScaleMode.Font;
			newEdit.Font = new Font("Terminal Mono", (float)10.0);

			editIsNew = isNew;
			if (isNew) {
				newEdit.Text = "New host entry";
			} else {
				newEdit.Text = "Edit host entry";
			}
			Button editCancel = new System.Windows.Forms.Button();
			editCancel.Location = new System.Drawing.Point(270,83);
			editCancel.Text = "Cancel";
			editCancel.Click += editCancelClick;
			
			Button editSave = new System.Windows.Forms.Button();
			editSave.Location = new System.Drawing.Point(190,83);
			editSave.Text = "Save";
			editSave.Click += editSaveClick;
			
			Label nameLabel = new Label();
			nameLabel.Text = "Name";
			nameLabel.Location = new Point(5, 5);
			nameLabel.Size = new Size(45, 20);
			
			editName = new TextBox();
			editName.Text = machine.name;
			editName.Size = new Size(150, 20);
			editName.Location = new Point(55, 5);
			
			Label tagLabel = new Label();
			tagLabel.Text = "Tag";
			tagLabel.Location = new Point(220, 5);
			tagLabel.Size = new Size(35, 20);
			
			editTag = new TextBox();
			editTag.Text = machine.tag;
			editTag.Size = new Size(85, 20);
			editTag.Location = new Point(260, 5);
			
			Label hostLabel = new Label();
			hostLabel.Text = "Host";
			hostLabel.Location = new Point(5, 30);
			hostLabel.Size = new Size(45, 20);
			
			editHost = new TextBox();
			editHost.Text = machine.host;
			editHost.Size = new Size(290, 20);
			editHost.Location = new Point(55, 30);
			
			Label keyLabel = new Label();
			keyLabel.Text = "Key";
			keyLabel.Location = new Point(5, 55);
			keyLabel.Size = new Size(35, 20);
			
			editKey = new TextBox();
			editKey.Text = machine.key;
			editKey.Size = new Size(290, 20);
			editKey.Location = new Point(55, 55);
			
			// draw a dialog
			newEdit.AutoScaleBaseSize = new System.Drawing.Size(5, 10);
			newEdit.ClientSize = new System.Drawing.Size(350, 110);
			newEdit.Controls.Add(editSave);
			newEdit.Controls.Add(editCancel);
			newEdit.Controls.Add(nameLabel);
			newEdit.Controls.Add(editName);
			newEdit.Controls.Add(tagLabel);
			newEdit.Controls.Add(editTag);
			newEdit.Controls.Add(hostLabel);
			newEdit.Controls.Add(editHost);
			newEdit.Controls.Add(keyLabel);
			newEdit.Controls.Add(editKey);
			newEdit.ShowDialog();
		}
		
		void passwordOkay(object o, System.EventArgs e) {
			HashAlgorithm hash = new SHA256Managed();
			string pass = passKey.Text;
			
			string ivs = "IPT PKD Knock" + pass;
			byte [] ivsb = new byte[ivs.Length];
			stringTobyte(ivs, ivsb);
			
			string keys = "client program for sending knock" + pass + "packets to ipt_pkd enabled host";
			byte [] keysb = new byte[keys.Length];
			stringTobyte(keys, keysb);
			
			byte [] tivb = hash.ComputeHash(ivsb);
			IVB = new byte[16];
			for (int j = 0; j < 16; j++) {
				IVB[j] = tivb[j];
			}
			KEYB = hash.ComputeHash(keysb);
			passD.Close();
		}
		
		private void passwordDialog() {
			passD = new Form();
			passD.FormBorderStyle = FormBorderStyle.FixedDialog;
			passD.ControlBox = false;
			passD.MinimizeBox = false;
			passD.MaximizeBox = false;

			passD.AutoScaleMode = AutoScaleMode.Font;
			passD.Font = new Font("Terminal Mono", (float)10.0);
			
			Label keyLabel = new Label();
			keyLabel.Text = "Enter Password";
			keyLabel.Size = new Size(200,20);
			keyLabel.Location = new Point(5, 5);
			
			passKey = new TextBox();
			passKey.PasswordChar = '*';
			passKey.Text = "";
			passKey.Size = new Size(200, 20);
			passKey.Location = new Point(5, 30);
			
			Button passBut = new Button();
			passBut.Text = "Okay";
			passBut.Location = new Point(50, 55);
			passBut.Click += passwordOkay;
			
			Button passExit = new Button();
			passExit.Text = "Exit";
			passExit.Location = new Point(125, 55);
			passExit.Click += btnExitClick;
			
			// draw a dialog
			passD.AutoScaleBaseSize = new System.Drawing.Size(5, 10);
			passD.ClientSize = new System.Drawing.Size(210, 80);
			
			passD.Controls.Add(keyLabel);
			passD.Controls.Add(passKey);
			passD.Controls.Add(passBut);
			passD.Controls.Add(passExit);
			
			passD.ShowDialog();
		}
		
		private byte [] _encrypt(string plain) {
			byte [] pb = new byte[256];
			byte [] eb = new byte[256];
			
			stringTobyte(plain, pb);
			
			keeper.Clear();
			keeper.IV = IVB;
			keeper.Key = KEYB;
			keeper.KeySize = 256;
			keeper.Mode = CipherMode.CBC;
			keeper.Padding = PaddingMode.Zeros;
			
			ICryptoTransform trapper = keeper.CreateEncryptor(KEYB, IVB);
			
			for (int j=0; j < 256; j += 16) {
				trapper.TransformBlock(pb, j, 16, eb, j);
			}
			
			return eb;
		}
		
		private byte [] _decrypt(byte[] eb, int length) {
			byte [] pb = new byte[256];
			
			keeper.Clear();
			keeper.IV = IVB;
			keeper.Key = KEYB;
			keeper.KeySize = 256;
			keeper.Mode = CipherMode.CBC;
			keeper.Padding = PaddingMode.Zeros;
			
			ICryptoTransform trapper = keeper.CreateDecryptor(KEYB, IVB);
			
			for (int j=0; j < length; j += 16) {
				trapper.TransformBlock(eb, j, 16, pb, j);
			}
			
			return pb;
		}
		
		private void _load_config() {
			System.Text.UTF8Encoding enc = new System.Text.UTF8Encoding();
			string          config = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),"ipt_pkd_knock");
			_host           host;
			Regex           reg = new Regex("_IPT_(.*?)_IPT_(.*?)_IPT_(.*?)_IPT_(.*)_PAD_.*", RegexOptions.Compiled);
			Match           matches;
			byte []         rblock = new byte[256];
			System.IO.FileStream rfile;
			int             items = 0;
			
			list.Clear();
			hostHash.Clear();
			
			try {
				rfile = System.IO.File.OpenRead(config);
			} catch {
				// need to check what the Open error was?
				badPass = false;
				return;
			}
			
			int n = rfile.Read(rblock, 0, 256);
			while (n > 0) {
				byte [] deb = _decrypt(rblock, n);
				string ds = enc.GetString(deb);
				if (reg.IsMatch(ds)) {
					matches = reg.Match(ds);
					host = new _host();
					host.name = ((matches.Groups)[1].Captures)[0].Value;
					host.host = ((matches.Groups)[2].Captures)[0].Value;
					host.key = ((matches.Groups)[3].Captures)[0].Value;
					host.tag = ((matches.Groups)[4].Captures)[0].Value;

					if (hostHash.ContainsKey(host.name) == false) {
						hostHash.Add(host.name, host);
						list.Items.Add(host.name);
					}
					items++;
				} else {
					if (items == 0) {
						rfile.Close();
						badPass = true;
						return;
					}
				}
				n = rfile.Read(rblock, 0, 256);
			}
			badPass = false;
			rfile.Close();
		}
		
		private void _save_config() {
			string    config = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),"ipt_pkd_knock");
			System.IO.FileStream wfile;

			try {
				wfile = new System.IO.FileStream(config, System.IO.FileMode.Create, System.IO.FileAccess.Write, System.IO.FileShare.None);
			} catch {
				return;
			}
			
			foreach (object o in hostHash.Values) {
				_host h = (_host)o;
				string tentry = "_IPT_" + h.name + "_IPT_" + h.host + "_IPT_" + h.key + "_IPT_" + h.tag + "_PAD_";
				byte [] eb = _encrypt(tentry);
				wfile.Write(eb, 0, eb.Length);
			}
			wfile.Close();
		}
	}
}