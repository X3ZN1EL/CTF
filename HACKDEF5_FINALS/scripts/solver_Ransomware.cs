
/* leax was here */  

using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Windows.Forms;
using Microsoft.Win32;

public class Program
{
    public static void Main()
    {    
        string[] codes = new string[]
        {
            "aSsEBGLIOv6L7lAooXDnJJK/6dU=",
            "o2pnGPVFJNhGiU+wS1uIW05D5js=",
            "WMYS05/Ym+ucsyNg0ks9Cpj4cyg=",
            "AB8kPpDrXnEICQr0qRN1VcaOs1E=",
            "6nxLEfibzE+vN+/KoQTXTPRD8X0="
        };
        foreach (int value in Enumerable.Range(0, 200))
        {
            string code = "GUHFJK";
            char c = (char)value;
            code += c.ToString();
            byte[] bytes = Encoding.UTF8.GetBytes(code);
            string text = Convert.ToBase64String(new SHA1CryptoServiceProvider().ComputeHash(bytes));
            if (!Enumerable.Contains<string>(codes, text)){
                if (text == "nYGgAcX2+YSNlfpg9/1OyNduNB8=")
                {
                    Console.WriteLine(text);
                    Console.WriteLine(code);
                }
                Console.WriteLine("Vaciando Code");
                code = "";
                text="";
            }
            Console.WriteLine(text);
            Console.WriteLine(code);
        }
    }
}
