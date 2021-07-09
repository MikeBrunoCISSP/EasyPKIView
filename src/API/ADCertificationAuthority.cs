using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Security.Cryptography.X509Certificates;

namespace EasyPKIView
{
    /// <summary>
    /// Describes a Microsoft Enterprise Certification Authority as stored in the "Enrollment Services" container in Active Directory
    /// </summary>
    public class ADCertificationAuthority : ADCSDirectoryEntry
    {
        /// <summary>
        /// An object containing the CA's public certificate
        /// </summary>
        public X509Certificate2 CACertificate { get; private set; }

        /// <summary>
        /// Indicates whether this CA is an Enterprise or Standalone CA.
        /// </summary>
        public bool IsEnterpriseCA { get; private set; }

        /// <summary>
        /// Indicates the DNS name of the server where the CA is installed.
        /// </summary>
        public string DNSHostName { get; private set; }

        /// <summary>
        /// Indicates the Distinguished name of the CA's Certificate
        /// </summary>
        public string CACertificateDN { get; private set; }

        /// <summary>
        /// The list of ADCertificateTemplates advertised as being available for enrollment on this CA.
        /// </summary>
        public List<ADCertificateTemplate> Templates { get; private set; } = new List<ADCertificateTemplate>();


        /// <summary>
        /// Indicates whether this CA advertises any certificate templates.
        /// </summary>
        public bool HasTemplates
        {
            get
            {
                return Templates.Count > 0;
            }
        }

        /// <summary>
        /// ADCertificationAuthority Constructor 1
        /// </summary>
        /// <param name="name">The common name of the CA</param>
        /// <param name="throwIfNotFound">If true, throw an exception if the template object cannot be loaded from Active Directory</param>
        public ADCertificationAuthority(string name, bool throwIfNotFound = true)
            : base(LdapUrls.EnrollmentService(name), ObjectClass.PKIEnrollmentService)
        {
            if (!IsValid)
            {
                throw new CertificationAuthorityNotFoundException(name);
            }
            SetFieldsFromDirectoryObject(throwIfNotFound);
        }

        /// <summary>
        /// ADCertificationAuthority Constructor 2
        /// </summary>
        /// <param name="CAEntry">The Active Directory entry pointing to this CA Enrollment Services object</param>
        /// <param name="throwIfNotFound">If true, throw an exception if the template object cannot be loaded from Active Directory</param>
        public ADCertificationAuthority(DirectoryEntry CAEntry, bool throwIfNotFound = true)
            : base(CAEntry, ObjectClass.PKIEnrollmentService)
        {
            if (!IsValid)
            {
                throw new CertificationAuthorityNotFoundException();
            }
            SetFieldsFromDirectoryObject(throwIfNotFound);
        }

        /// <summary>
        /// ADCertificationAuthority Constructor 3
        /// </summary>
        /// <param name="CACert">The CA's public certificate</param>
        /// <param name="throwIfNotFound">If true, throw an exception if the template object cannot be loaded from Active Directory</param>
        public ADCertificationAuthority(X509Certificate2 CACert, bool throwIfNotFound = true)
            : this(CACert.Subject.Replace(@"CN=", string.Empty).Split(',')[0], throwIfNotFound)
        { }

        private void SetFieldsFromDirectoryObject(bool throwIfNotFound)
        {
            if (!IsValid && throwIfNotFound)
            {
                throw new CertificationAuthorityNotFoundException();
            }

            CACertificate = new X509Certificate2((byte[])DirEntry.Properties[PropertyIndex.CACertificate].Value);
            IsEnterpriseCA = (int)DirEntry.Properties[PropertyIndex.Flags].Value == 10;
            DNSHostName = DirEntry.Properties[PropertyIndex.DNSHostName].Value.ToString();
            CACertificateDN = DirEntry.Properties[PropertyIndex.CACertificateDN].Value.ToString();
            GetTemplates(DirEntry);
        }

        private void GetTemplates(DirectoryEntry CAEntry)
        {
            CAEntry.RefreshCache(new string[] { PropertyIndex.CertificateTemplates });
            object[] TemplateNames;

            try
            {
                TemplateNames = (object[])CAEntry.Properties[PropertyIndex.CertificateTemplates].Value;
            }
            catch
            {
                //If there's only a single template, it won't cast as an array automatically.
                TemplateNames = new object[] { CAEntry.Properties[PropertyIndex.CertificateTemplates].Value };
            }

            if (TemplateNames != null)
            {
                for (int x=0; x<TemplateNames.Length; x++)
                {
                    var Tmpl = new ADCertificateTemplate(TemplateNames[x].ToString(), throwIfNotFound: false);
                    if (Tmpl.IsValid)
                    {
                        Templates.Add(Tmpl);
                    }
                }
            }
        }

        /// <summary>
        /// Loads all CAs in the current Active Directory forest
        /// </summary>
        /// <returns>A list of ADCertificationAuthority objects</returns>
        public static List<ADCertificationAuthority> GetAll()
        {
            List<ADCertificationAuthority> Collection = new List<ADCertificationAuthority>();
            ADCertificationAuthority CA;

            using (DirectoryEntry EnrollmentServicesContainer = new DirectoryEntry(LdapUrls.EnrollmentServicesContainer))
            {
                foreach (DirectoryEntry CAEntry in EnrollmentServicesContainer.Children)
                {
                    CA = new ADCertificationAuthority(CAEntry, throwIfNotFound: false);
                    if (CA.IsValid)
                    {
                        Collection.Add(CA);
                    }
                }
            }

            return Collection;
        }
    }
}
