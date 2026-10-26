using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;

namespace BaiTap2_RSA
{
    public partial class Form1 : Form
    {
        private RSA rsaKey;
        private TabControl tabControl = null!;

        // UI Tab 1-4: Key & PEM
        private TextBox txtPublicPem = null!, txtPrivatePem = null!, txtModulusN = null!, txtPublicE = null!, txtPrivateD = null!;

        // UI Tab 5-7: Crypto
        private TextBox txtDataInput = null!, txtCipherOutput = null!, txtDecryptedOutput = null!;
        private Label lblSpeedEnc = null!, lblSpeedDec = null!;

        // UI Tab 8: Hash
        private TextBox txtHashInput = null!, txtHashOutput = null!;
        private Label lblBitChange = null!;

        // UI Tab 9: Sign
        private TextBox txtSignInput = null!, txtSignatureOutput = null!;
        private Label lblVerifyStatus = null!;

        public Form1()
        {
            InitializeComponent();
            rsaKey = RSA.Create(2048);
            InitCustomGUI();
        }

        private void Form1_Load(object? sender, EventArgs e) { }

        private void InitCustomGUI()
        {
            this.Text = "BÀI TẬP 2: MÃ HÓA RSA - BĂM SHA256 & CHỮ KÝ SỐ";
            this.Size = new Size(780, 680);
            this.StartPosition = FormStartPosition.CenterScreen;

            tabControl = new TabControl { Dock = DockStyle.Fill };

            TabPage tabKeys = new TabPage("1-4. Quản lý Khóa RSA & PEM");
            BuildTabKeys(tabKeys);

            TabPage tabCrypto = new TabPage("5-7. Mã hóa, Giải mã & Tốc độ");
            BuildTabCrypto(tabCrypto);

            TabPage tabHash = new TabPage("8. Băm SHA-256 (Thác đổ)");
            BuildTabHash(tabHash);

            TabPage tabSign = new TabPage("9. Chữ ký số (RSA-PSS)");
            BuildTabSign(tabSign);

            tabControl.TabPages.AddRange(new TabPage[] { tabKeys, tabCrypto, tabHash, tabSign });
            this.Controls.Add(tabControl);
        }

        #region TAB 1: QUẢN LÝ KHÓA RSA
        private void BuildTabKeys(TabPage page)
        {
            Button btnGenKey = new Button { Text = "1. Sinh Cặp Khóa 2048-bit", Location = new Point(15, 10), Size = new Size(180, 30) };
            Button btnExportKey = new Button { Text = "2. Xuất Khóa ra File PEM", Location = new Point(205, 10), Size = new Size(180, 30) };
            Button btnImportKey = new Button { Text = "4. Import Khóa từ File PEM", Location = new Point(395, 10), Size = new Size(180, 30) };

            Label lblPub = new Label { Text = "PUBLIC KEY (PEM format):", Location = new Point(15, 50), AutoSize = true };
            txtPublicPem = new TextBox { Location = new Point(15, 70), Size = new Size(360, 160), Multiline = true, ScrollBars = ScrollBars.Vertical, ReadOnly = true };

            Label lblPriv = new Label { Text = "PRIVATE KEY (PEM format):", Location = new Point(390, 50), AutoSize = true };
            txtPrivatePem = new TextBox { Location = new Point(390, 70), Size = new Size(360, 160), Multiline = true, ScrollBars = ScrollBars.Vertical, ReadOnly = true };

            GroupBox gbParams = new GroupBox { Text = " 3 & 4. Trích xuất Thành phần Khóa (Modulus n, Exponents e, d) ", Location = new Point(15, 240), Size = new Size(735, 360) };
            Label l1 = new Label { Text = "Modulus (n) [Hex]:", Location = new Point(15, 25), AutoSize = true };
            txtModulusN = new TextBox { Location = new Point(15, 45), Size = new Size(705, 70), Multiline = true, ScrollBars = ScrollBars.Vertical, ReadOnly = true };

            Label l2 = new Label { Text = "Public Exponent (e) [Hex]:", Location = new Point(15, 125), AutoSize = true };
            txtPublicE = new TextBox { Location = new Point(15, 145), Size = new Size(705, 30), ReadOnly = true };

            Label l3 = new Label { Text = "Private Exponent (d) [Hex]:", Location = new Point(15, 185), AutoSize = true };
            txtPrivateD = new TextBox { Location = new Point(15, 205), Size = new Size(705, 140), Multiline = true, ScrollBars = ScrollBars.Vertical, ReadOnly = true };

            gbParams.Controls.AddRange(new Control[] { l1, txtModulusN, l2, txtPublicE, l3, txtPrivateD });
            page.Controls.AddRange(new Control[] { btnGenKey, btnExportKey, btnImportKey, lblPub, txtPublicPem, lblPriv, txtPrivatePem, gbParams });

            btnGenKey.Click += (s, e) => GenerateNewRSAKeyPair();
            btnExportKey.Click += (s, e) => ExportKeysToPEMFiles();
            btnImportKey.Click += (s, e) => ImportKeysFromPEMFiles();
        }

        private void GenerateNewRSAKeyPair()
        {
            rsaKey = RSA.Create(2048);
            txtPublicPem.Text = rsaKey.ExportRSAPublicKeyPem();
            txtPrivatePem.Text = rsaKey.ExportPkcs8PrivateKeyPem();
            DisplayKeyParameters();
            MessageBox.Show("Đã sinh cặp khóa RSA 2048-bit mới!", "Thông báo");
        }

        private void DisplayKeyParameters()
        {
            RSAParameters p = rsaKey.ExportParameters(true);
            txtModulusN.Text = Convert.ToHexString(p.Modulus!);
            txtPublicE.Text = Convert.ToHexString(p.Exponent!) + $" (Giá trị thập phân: {BitConverter.ToUInt32(PadLeft(p.Exponent!, 4), 0)})";
            txtPrivateD.Text = Convert.ToHexString(p.D!);
        }

        private byte[] PadLeft(byte[] src, int length)
        {
            byte[] res = new byte[length];
            Buffer.BlockCopy(src, 0, res, length - src.Length, src.Length);
            Array.Reverse(res);
            return res;
        }

        private void ExportKeysToPEMFiles()
        {
            File.WriteAllText("public_key.pem", rsaKey.ExportRSAPublicKeyPem());
            File.WriteAllText("private_key.pem", rsaKey.ExportPkcs8PrivateKeyPem());
            MessageBox.Show("Đã xuất 2 file: public_key.pem và private_key.pem!", "Thành công");
        }

        private void ImportKeysFromPEMFiles()
        {
            OpenFileDialog ofd = new OpenFileDialog { Filter = "PEM Files|*.pem|All Files|*.*" };
            if (ofd.ShowDialog() == DialogResult.OK)
            {
                string pemContent = File.ReadAllText(ofd.FileName);
                rsaKey.ImportFromPem(pemContent);
                txtPublicPem.Text = rsaKey.ExportRSAPublicKeyPem();
                txtPrivatePem.Text = rsaKey.ExportPkcs8PrivateKeyPem();
                DisplayKeyParameters();
                MessageBox.Show("Đã Nạp thành công và trích xuất thông số khóa từ file PEM!", "Thông báo");
            }
        }
        #endregion

        #region TAB 2: MÃ HÓA, GIẢI MÃ & TỐC ĐỘ
        private void BuildTabCrypto(TabPage page)
        {
            Label l1 = new Label { Text = "Dữ liệu nguồn (Khóa AES 32 bytes Base64 hoặc chuỗi < 190 bytes):", Location = new Point(15, 15), AutoSize = true };
            txtDataInput = new TextBox { Text = "K3g9a1ZqQ18xOXg0a2ZzZGZzZGZzZGZzZGZzZGZzZGE=", Location = new Point(15, 35), Size = new Size(735, 30) };

            Button btnEnc = new Button { Text = "5. Mã hóa Dữ liệu (Public Key)", Location = new Point(15, 75), Size = new Size(220, 35) };
            Button btnDec = new Button { Text = "6. Giải mã Dữ liệu (Private Key)", Location = new Point(255, 75), Size = new Size(220, 35) };
            Button btnBenchmark = new Button { Text = "7. Đánh giá Tốc độ Enc vs Dec", Location = new Point(495, 75), Size = new Size(255, 35) };

            Label l2 = new Label { Text = "Kết quả Mã hóa (Base64) -> Lưu File:", Location = new Point(15, 125), AutoSize = true };
            txtCipherOutput = new TextBox { Location = new Point(15, 145), Size = new Size(735, 100), Multiline = true, ReadOnly = true };

            Label l3 = new Label { Text = "Kết quả Giải mã thu được:", Location = new Point(15, 255), AutoSize = true };
            txtDecryptedOutput = new TextBox { Location = new Point(15, 275), Size = new Size(735, 60), Multiline = true, ReadOnly = true };

            lblSpeedEnc = new Label { Text = "Thời gian Mã hóa (Public Key e): -- ms", Location = new Point(15, 355), AutoSize = true, Font = new Font(this.Font, FontStyle.Bold) };
            lblSpeedDec = new Label { Text = "Thời gian Giải mã (Private Key d): -- ms", Location = new Point(15, 385), AutoSize = true, Font = new Font(this.Font, FontStyle.Bold) };

            page.Controls.AddRange(new Control[] { l1, txtDataInput, btnEnc, btnDec, btnBenchmark, l2, txtCipherOutput, l3, txtDecryptedOutput, lblSpeedEnc, lblSpeedDec });

            btnEnc.Click += (s, e) => EncryptData();
            btnDec.Click += (s, e) => DecryptData();
            btnBenchmark.Click += (s, e) => RunBenchmark();
        }

        private void EncryptData()
        {
            byte[] rawBytes = Encoding.UTF8.GetBytes(txtDataInput.Text);
            if (rawBytes.Length > 190)
            {
                MessageBox.Show("Dữ liệu quá lớn! RSA 2048-bit với OAEP Padding chỉ mã hóa tối đa 190 bytes.", "Cảnh báo");
                return;
            }

            byte[] cipherBytes = rsaKey.Encrypt(rawBytes, RSAEncryptionPadding.OaepSHA256);
            string base64Cipher = Convert.ToBase64String(cipherBytes);
            txtCipherOutput.Text = base64Cipher;
            File.WriteAllText("encrypted_data.bin", base64Cipher);
            MessageBox.Show("Mã hóa hoàn tất và đã lưu file 'encrypted_data.bin'!", "Thông báo");
        }

        private void DecryptData()
        {
            if (string.IsNullOrEmpty(txtCipherOutput.Text)) return;
            byte[] cipherBytes = Convert.FromBase64String(txtCipherOutput.Text);
            byte[] decryptedBytes = rsaKey.Decrypt(cipherBytes, RSAEncryptionPadding.OaepSHA256);
            string resultText = Encoding.UTF8.GetString(decryptedBytes);
            txtDecryptedOutput.Text = resultText;

            bool isMatch = (resultText == txtDataInput.Text);
            MessageBox.Show($"So sánh dữ liệu giải mã và dữ liệu nguồn:\n{(isMatch ? "TRÙNG KHỚP 100% (MATCH)" : "KHÔNG TRÙNG KHỚP")}", "Kết quả");
        }

        private void RunBenchmark()
        {
            byte[] rawBytes = Encoding.UTF8.GetBytes(txtDataInput.Text);
            int iterations = 100;

            Stopwatch sw = Stopwatch.StartNew();
            byte[]? cipherBytes = null;
            for (int i = 0; i < iterations; i++)
            {
                cipherBytes = rsaKey.Encrypt(rawBytes, RSAEncryptionPadding.OaepSHA256);
            }
            sw.Stop();
            double encAvg = sw.Elapsed.TotalMilliseconds / iterations;
            lblSpeedEnc.Text = $"Thời gian Mã hóa trung bình (Public Key e=65537): {encAvg:F4} ms";

            sw.Restart();
            for (int i = 0; i < iterations; i++)
            {
                if (cipherBytes != null)
                {
                    rsaKey.Decrypt(cipherBytes, RSAEncryptionPadding.OaepSHA256);
                }
            }
            sw.Stop();
            double decAvg = sw.Elapsed.TotalMilliseconds / iterations;
            lblSpeedDec.Text = $"Thời gian Giải mã trung bình (Private Key d lớn): {decAvg:F4} ms (Chậm hơn {decAvg / encAvg:F1} lần!)";
        }
        #endregion

        #region TAB 3: BĂM SHA-256 & EFFECT THÁC ĐỔ
        private void BuildTabHash(TabPage page)
        {
            Label l1 = new Label { Text = "Nhập Chuỗi Đầu Vào (Thay đổi 1 ký tự để xem hiệu ứng Thác đổ - Avalanche Effect):", Location = new Point(15, 15), AutoSize = true };
            txtHashInput = new TextBox { Text = "An toàn thông tin 2026", Location = new Point(15, 35), Size = new Size(735, 30) };

            Label l2 = new Label { Text = "Mã Băm SHA-256 (256-bit = 64 ký tự Hex):", Location = new Point(15, 80), AutoSize = true };
            txtHashOutput = new TextBox { Location = new Point(15, 100), Size = new Size(735, 40), Font = new Font("Courier New", 10, FontStyle.Bold), ReadOnly = true };

            lblBitChange = new Label { Text = "Số bits thay đổi so với lần nhập trước: 0 / 256 bits (0%)", Location = new Point(15, 160), AutoSize = true, ForeColor = Color.Blue, Font = new Font(this.Font, FontStyle.Bold) };

            page.Controls.AddRange(new Control[] { l1, txtHashInput, l2, txtHashOutput, lblBitChange });

            txtHashInput.TextChanged += TxtHashInput_TextChanged;
            TxtHashInput_TextChanged(this, EventArgs.Empty);
        }

        private string lastHashHex = "";
        private void TxtHashInput_TextChanged(object? sender, EventArgs e)
        {
            byte[] inputBytes = Encoding.UTF8.GetBytes(txtHashInput.Text);
            byte[] hashBytes = SHA256.HashData(inputBytes);
            string currentHashHex = Convert.ToHexString(hashBytes);
            txtHashOutput.Text = currentHashHex;

            if (!string.IsNullOrEmpty(lastHashHex) && lastHashHex.Length == currentHashHex.Length)
            {
                byte[] lastBytes = Convert.FromHexString(lastHashHex);
                int changedBits = CountDifferentBits(lastBytes, hashBytes);
                double percent = (double)changedBits / 256 * 100;
                lblBitChange.Text = $"Hiệu ứng Thác đổ (Avalanche Effect): Thay đổi {changedBits} / 256 bits ({percent:F1}%)";
            }
            lastHashHex = currentHashHex;
        }

        private int CountDifferentBits(byte[] b1, byte[] b2)
        {
            int diff = 0;
            for (int i = 0; i < b1.Length; i++)
            {
                byte xor = (byte)(b1[i] ^ b2[i]);
                while (xor > 0)
                {
                    diff += xor & 1;
                    xor >>= 1;
                }
            }
            return diff;
        }
        #endregion

        #region TAB 4: CHỮ KÝ SỐ NGẪU NHIÊN (RSA-PSS)
        private void BuildTabSign(TabPage page)
        {
            Label l1 = new Label { Text = "Nội dung Thông điệp cần ký:", Location = new Point(15, 15), AutoSize = true };
            txtSignInput = new TextBox { Text = "Hợp đồng chuyển nhượng bản quyền phần mềm 2026", Location = new Point(15, 35), Size = new Size(735, 30) };

            Button btnSign = new Button { Text = "9. Tạo Chữ Ký Số (RSA-PSS)", Location = new Point(15, 75), Size = new Size(250, 35) };
            Button btnVerify = new Button { Text = "Xác thực Chữ Ký Số (Verify)", Location = new Point(280, 75), Size = new Size(250, 35) };

            Label l2 = new Label { Text = "Chữ ký số thu được (RSA-PSS Base64) - Bấm Ký nhiều lần để thấy Chữ Ký KHÁC NHAU:", Location = new Point(15, 125), AutoSize = true };
            txtSignatureOutput = new TextBox { Location = new Point(15, 145), Size = new Size(735, 120), Multiline = true, ReadOnly = true };

            lblVerifyStatus = new Label { Text = "Trạng thái xác thực: Chưa kiểm tra", Location = new Point(15, 280), AutoSize = true, Font = new Font(this.Font, FontStyle.Bold) };

            page.Controls.AddRange(new Control[] { l1, txtSignInput, btnSign, btnVerify, l2, txtSignatureOutput, lblVerifyStatus });

            btnSign.Click += (s, e) => SignDataRandomized();
            btnVerify.Click += (s, e) => VerifySignature();
        }

        private void SignDataRandomized()
        {
            byte[] dataBytes = Encoding.UTF8.GetBytes(txtSignInput.Text);

            byte[] signature = rsaKey.SignData(dataBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
            txtSignatureOutput.Text = Convert.ToBase64String(signature);
            lblVerifyStatus.Text = "Đã ký thành công bằng RSA-PSS! (Nhấn 'Tạo Chữ Ký Số' lại để thấy chuỗi thay đổi)";
            lblVerifyStatus.ForeColor = Color.DarkGreen;
        }

        private void VerifySignature()
        {
            if (string.IsNullOrEmpty(txtSignatureOutput.Text)) return;
            byte[] dataBytes = Encoding.UTF8.GetBytes(txtSignInput.Text);
            byte[] signatureBytes = Convert.FromBase64String(txtSignatureOutput.Text);

            bool isValid = rsaKey.VerifyData(dataBytes, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

            if (isValid)
            {
                lblVerifyStatus.Text = "KẾT QUẢ XÁC THỰC: CHỮ KÝ HỢP LỆ (VERIFIED SUCCESS)";
                lblVerifyStatus.ForeColor = Color.Green;
            }
            else
            {
                lblVerifyStatus.Text = "KẾT QUẢ XÁC THỰC: CHỮ KÝ KHÔNG HỢP LỆ (VERIFICATION FAILED)";
                lblVerifyStatus.ForeColor = Color.Red;
            }
        }
        #endregion
    }
}