using System;
using System.Windows.Forms;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.IO;
using System.Drawing;
using Microsoft.Win32;

namespace ScreenLockerPublic
{
    // A simple dialog to set the password before locking
    public class SetupForm : Form
    {
        private TextBox txtSetPassword;
        private Button btnLock;
        public string Password { get; private set; }

        public SetupForm()
        {
            this.Text = "Configurer le verrouillage";
            this.Size = new Size(350, 180);
            this.FormBorderStyle = FormBorderStyle.FixedDialog;
            this.StartPosition = FormStartPosition.CenterScreen;
            this.MaximizeBox = false;

            Label lbl = new Label() { Text = "Définissez le mot de passe pour cette session :", Location = new Point(20, 20), AutoSize = true };
            txtSetPassword = new TextBox() { Location = new Point(20, 50), Width = 280, PasswordChar = '*' };
            btnLock = new Button() { Text = "Verrouiller maintenant", Location = new Point(100, 90), Width = 150, Height = 30 };
            
            btnLock.Click += (s, e) => {
                if (string.IsNullOrEmpty(txtSetPassword.Text)) {
                    MessageBox.Show("Veuillez entrer un mot de passe.");
                    return;
                }
                this.Password = txtSetPassword.Text;
                this.DialogResult = DialogResult.OK;
                this.Close();
            };

            this.Controls.AddRange(new Control[] { lbl, txtSetPassword, btnLock });
        }
    }

    public class LockerForm : Form
    {
        private const int WH_KEYBOARD_LL = 13;
        private const int WM_KEYDOWN = 0x0100;
        private const int WM_SYSKEYDOWN = 0x0104;
        private static LowLevelKeyboardProc _proc = HookCallback;
        private static IntPtr _hookID = IntPtr.Zero;

        private TextBox txtPassword;
        private string sessionPassword;
        private string logFile;

        public LockerForm(string password)
        {
            this.sessionPassword = password;
            this.logFile = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "lock_history_public.csv");
            
            InitializeComponent();
            _hookID = SetHook(_proc);
            LogEvent("LOCK");
            ToggleTaskManager(true);
        }

        private void InitializeComponent()
        {
            this.SuspendLayout();
            this.BackColor = Color.FromArgb(40, 40, 45); // Dark Modern Theme
            this.FormBorderStyle = FormBorderStyle.None;
            this.WindowState = FormWindowState.Maximized;
            this.TopMost = true;

            Label lblIcon = new Label() {
                Text = "🔐", Font = new Font("Segoe UI", 80), ForeColor = Color.White,
                AutoSize = true, Location = new Point((Screen.PrimaryScreen.Bounds.Width / 2) - 60, (Screen.PrimaryScreen.Bounds.Height / 2) - 250)
            };
            this.Controls.Add(lblIcon);

            Label lblText = new Label() {
                Text = "Session Protégée", Font = new Font("Segoe UI", 28, FontStyle.Bold), ForeColor = Color.White,
                AutoSize = true, Location = new Point((Screen.PrimaryScreen.Bounds.Width / 2) - 160, (Screen.PrimaryScreen.Bounds.Height / 2) - 100)
            };
            this.Controls.Add(lblText);

            txtPassword = new TextBox() {
                PasswordChar = '●', Font = new Font("Segoe UI", 24), Width = 350,
                Location = new Point((Screen.PrimaryScreen.Bounds.Width / 2) - 175, (Screen.PrimaryScreen.Bounds.Height / 2)),
                TextAlign = HorizontalAlignment.Center, BackColor = Color.FromArgb(60, 60, 65), ForeColor = Color.White, BorderStyle = BorderStyle.None
            };
            txtPassword.KeyDown += (s, e) => { if (e.KeyCode == Keys.Enter) CheckPassword(); };
            this.Controls.Add(txtPassword);

            Button btnUnlock = new Button() {
                Text = "DÉVERROUILLER", Font = new Font("Segoe UI", 12, FontStyle.Bold), Width = 200, Height = 50,
                BackColor = Color.FromArgb(0, 120, 215), ForeColor = Color.White, FlatStyle = FlatStyle.Flat,
                Location = new Point((Screen.PrimaryScreen.Bounds.Width / 2) - 100, (Screen.PrimaryScreen.Bounds.Height / 2) + 80)
            };
            btnUnlock.FlatAppearance.BorderSize = 0;
            btnUnlock.Click += (s, e) => CheckPassword();
            this.Controls.Add(btnUnlock);

            this.FormClosing += (s, e) => { if (e.CloseReason == CloseReason.UserClosing) e.Cancel = true; };
            this.ResumeLayout(false);
        }

        private void CheckPassword()
        {
            if (txtPassword.Text == sessionPassword)
            {
                LogEvent("UNLOCK");
                ToggleTaskManager(false);
                UnhookWindowsHookEx(_hookID);
                Application.Exit();
            }
            else
            {
                LogEvent("FAILED ATTEMPT", "Mot de passe incorrect saisi.");
                MessageBox.Show("Mot de passe incorrect.", "Sécurité", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                txtPassword.Clear();
            }
        }

        private void LogEvent(string type, string details = "")
        {
            try
            {
                string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
                string line = string.Format("\"{0}\",\"{1}\",\"{2}\"", timestamp, type, details);
                if (!File.Exists(logFile)) File.WriteAllText(logFile, "Timestamp,Event,Details" + Environment.NewLine, System.Text.Encoding.UTF8);
                File.AppendAllText(logFile, line + Environment.NewLine, System.Text.Encoding.UTF8);
            }
            catch { }
        }

        private void ToggleTaskManager(bool disabled)
        {
            try {
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Policies\System")) {
                    if (disabled) key.SetValue("DisableTaskMgr", 1, RegistryValueKind.DWord);
                    else key.DeleteValue("DisableTaskMgr", false);
                }
            } catch { }
        }

        private static IntPtr SetHook(LowLevelKeyboardProc proc)
        {
            using (Process curProcess = Process.GetCurrentProcess())
            using (ProcessModule curModule = curProcess.MainModule)
                return SetWindowsHookEx(WH_KEYBOARD_LL, proc, GetModuleHandle(curModule.ModuleName), 0);
        }

        private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);

        private static IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam)
        {
            if (nCode >= 0 && (wParam == (IntPtr)WM_KEYDOWN || wParam == (IntPtr)WM_SYSKEYDOWN))
            {
                Keys key = (Keys)Marshal.ReadInt32(lParam);
                bool isWin = (key == Keys.LWin || key == Keys.RWin);
                bool isAlt = (Control.ModifierKeys & Keys.Alt) != 0;
                bool isTab = (key == Keys.Tab);
                bool isF4 = (key == Keys.F4);
                bool isEsc = (key == Keys.Escape);
                bool isCtrl = (Control.ModifierKeys & Keys.Control) != 0;

                if (isWin || (isAlt && isTab) || (isAlt && isF4) || (isCtrl && isEsc)) return (IntPtr)1;
            }
            return CallNextHookEx(_hookID, nCode, wParam, lParam);
        }

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)] private static extern IntPtr SetWindowsHookEx(int idHook, LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);
        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool UnhookWindowsHookEx(IntPtr hhk);
        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)] private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)] private static extern IntPtr GetModuleHandle(string lpModuleName);

        [STAThread]
        public static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            
            using (var setup = new SetupForm())
            {
                if (setup.ShowDialog() == DialogResult.OK)
                {
                    Application.Run(new LockerForm(setup.Password));
                }
            }
        }
    }
}
