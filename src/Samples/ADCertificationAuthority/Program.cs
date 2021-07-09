using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using EasyPKIView;

namespace CA
{
    class Program
    {
        static void Main(string[] args)
        {
            //Collect data about all enterprise sub CAS published in your AD 
            var AllCAs = ADCertificationAuthority.GetAll();
            var CAs = AllCAs.Where(p => p.Templates.Where(q => q.RequiresPrivateKeyArchival).Any()).ToList();

            //Lets pop the first one off and have a look 
            var FirstOne = AllCAs.First();

            //We can capture the CA cert as a X5Ø9Certificate2 objelt 
            X509Certificate2 CACert = FirstOne.CACertificate;

            //Captures the distinguished name of the CA certificate 
            string CACertDN = FirstOne.CACertificateDN;

            //Captures the display name of the CA 
            string CAName = FirstOne.DisplayName;

            //Captures the distinguished name of the CA Enrollment Services AD object 
            string ESDN = FirstOne.DistinguishedName;

            //Captures the host name where the CA is installed 
            string host = FirstOne.DNSHostName;

            // Indicates whether the CA has any certificate templates assigned to it
            // This will always be true based on our Linq query
            bool anyTemplates = FirstOne.HasTemplates;

            // Indicates whether this CA is Enterprise or Stand-alone 
            bool isEnterprise = FirstOne.IsEnterpriseCA;

            //Captures the collection of all certificate templates assigned to this CA 
            List<ADCertificateTemplate> Templates = FirstOne.Templates;
        }
    }
}
