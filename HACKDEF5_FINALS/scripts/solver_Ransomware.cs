/* 
DarkSide
leax was here 
*/

using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

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
        bool flag = false;
        string code = ""; //GUHFJK
        string password = "";
        while (!flag){
            foreach (int value in Enumerable.Range(0, 200))
            {
                char c = (char)value;
                code += password + c.ToString();
                byte[] bytes = Encoding.UTF8.GetBytes(code);
                string text = Convert.ToBase64String(new SHA1CryptoServiceProvider().ComputeHash(bytes));
                if (!Enumerable.Contains<string>(codes, text))
                {
                    if (text == "nYGgAcX2+YSNlfpg9/1OyNduNB8=" || password == "nYGgAcX2+YSNlfpg9/1OyNduNB8=")
                    {
                        Console.WriteLine("Cracked: "+ code);
                        flag = true;
                    }
                    text = "";
                    code = "";
                }
                else
                {
                    Console.WriteLine(password);
                    password = password + c.ToString();
                    text = "";
                    code = "";
                }
                
            } 
        }
    }
}
