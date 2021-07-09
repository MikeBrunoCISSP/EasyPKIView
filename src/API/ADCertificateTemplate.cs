using System;
using System.Linq;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.CompilerServices;
using System.Security.Principal;

namespace EasyPKIView
{
    /// <summary>
    /// Describes a certificate template as stored in the "Certificate Templates" container in Active Directory
    /// </summary>
    public class ADCertificateTemplate : ADCSDirectoryEntry
    {
        private static bool loadedAllTemplates = false;
        private static List<ADCertificateTemplate> all = new List<ADCertificateTemplate>();

        /// <summary>
        /// The object ID of the certificate template
        /// </summary>
        public string Oid { get; private set; }

        /// <summary>
        /// The certificate template version. Version 1 = Compatible with Windows 2000 and up, Version 2 = WS2003 and up, and so on.
        /// </summary>
        public int Version { get; private set; }

        /// <summary>
        /// The list of key usages asserted by certificates issued using this certificate template
        /// </summary>
        public List<KeyUsage> KeyUsages { get; private set; }

        /// <summary>
        /// The list of extended key usages (also known as application policies) asserted by certificates issued using this certificate template
        /// </summary>
        public List<ExtendedKeyUsage> ExtendedKeyUsages { get; private set; }

        /// <summary>
        /// The number of certificate request agents a certificate request must be signed by in order to obtain a certificate using this template
        /// </summary>
        public int RASignaturesRequired { get; private set; }

        /// <summary>
        /// The minimum key size of the public key enforced by this certificate template
        /// </summary>
        public int MinimumKeySize { get; private set; }

        /// <summary>
        /// The amount of time for which certificates issued from this template are valid
        /// </summary>
        public TimeSpan ValidityPeriod { get; private set; }

        /// <summary>
        /// A set of bit switches that control additonal certificate template behaviors
        /// </summary>
        public int PrivateKeyFlags { get; private set; }

        /// <summary>
        /// Indicates whether this certificate template requires private key archival
        /// </summary>
        public bool RequiresPrivateKeyArchival => (PrivateKeyFlags & CertificateTemplateFlag.RequirePrivateKeyArchival) != 0;

        /// <summary>
        /// Indicates whether the private key associated with certificates issued from this template should be exportable from the host on which they were created (only meaningful on Windows clients)
        /// </summary>
        public bool ExportablePrivateKey => (PrivateKeyFlags & CertificateTemplateFlag.ExportablePrivateKey) != 0;

        /// <summary>
        /// Indicates whether this certificate template should enforce strong private key protection.  See https://tinyurl.com/y25l2h8p for more details.
        /// </summary>
        public bool RequiresStrongKeyProtection => (PrivateKeyFlags & CertificateTemplateFlag.StrongKeyProtectionRequired) != 0;

        /// <summary>
        /// Indicates whether this certificate template should require TPM Key Attestation. See https://tinyurl.com/y9c6oxnp for more details.
        /// </summary>
        public bool KeyAttestationRequired => (PrivateKeyFlags & CertificateTemplateFlag.KeyAttestationRequired) != 0;

        /// <summary>
        /// Indicates whether this certificate template should use TPM Key Attestation if the client supports it.
        /// </summary>
        public bool KeyAttestationPreferred => (PrivateKeyFlags & CertificateTemplateFlag.KeyAttestationPreferred) != 0;

        /// <summary>
        /// Indicates whether this certificate template requires the CA to assert a TPM Key Attestation issuance policy OID on issued certificates
        /// </summary>
        public bool AssertsKeyAttestationPolicy => KeyAttestationPreferred && (PrivateKeyFlags & CertificateTemplateFlag.AllowKeyAttestationWithoutPolicyAssertion) == 0;

        /// <summary>
        /// The collection of AD identity principals that have rights on the certificate template along with the specification of what those rights are
        /// </summary>
        public List<ADCertificateTemplateAccessRule> AccessRules { get; private set; } = new List<ADCertificateTemplateAccessRule>();

        internal KeyAttestationType attestationType
        {
            get
            {
                if ((PrivateKeyFlags & (int)KeyAttestationType.AccountCredentials) != 0)
                {
                    return KeyAttestationType.AccountCredentials;
                }

                if ((PrivateKeyFlags & (int)KeyAttestationType.SigningCertificate) != 0)
                {
                    return KeyAttestationType.SigningCertificate;
                }

                if ((PrivateKeyFlags & (int)KeyAttestationType.PreSharedKey) != 0)
                {
                    return KeyAttestationType.PreSharedKey;
                }
                else
                {
                    return KeyAttestationType.None;
                }
            }
        }

        /// <summary>
        /// Indicates the TPM Key Attestation type required by this certificate template (if applicable)
        /// </summary>
        public string AttestationType => attestationType.GetDescription();

        /// <summary>
        /// ADCertificateTemplate Constructor 1
        /// </summary>
        /// <param name="name">The Name attribute of the certificate template as indicated in Active Directory</param>
        /// <param name="throwIfNotFound">If true, throw an exception if the template object cannot be loaded from Active Directory</param>
        public ADCertificateTemplate(string name, bool throwIfNotFound = true)
            : base(LdapUrls.CertificateTemplate(name), ObjectClass.PKICertificateTemplate)
        {
            SetFieldsFromDirectoryObject(throwIfNotFound);
            GetAccessRules();
        }

        /// <summary>
        /// ADCertificateTemplate Constructor 2
        /// </summary>
        /// <param name="TemplateEntry">The Active Directory entry pointing to this certificate template</param>
        /// <param name="throwIfNotFound">If true, throw an exception if the template object cannot be loaded from Active Directory</param>
        public ADCertificateTemplate(DirectoryEntry TemplateEntry, bool throwIfNotFound = true)
            : base(TemplateEntry, ObjectClass.PKICertificateTemplate)
        {
            SetFieldsFromDirectoryObject(throwIfNotFound);
            GetAccessRules();
        }

        /// <summary>
        /// ADCertificateTemplate Constructor 3
        /// </summary>
        /// <param name="Cert">A certificate object which was issued using the desired certificate template</param>
        public ADCertificateTemplate(X509Certificate2 Cert)
        {
            string templateOid = string.Empty;
            ADCertificateTemplate FoundTemplate;

            foreach(X509Extension Extension in Cert.Extensions)
            {
                if (Extension.Oid.Value.Matches(Constants.CertificateTemplateExtensionOid))
                {
                    templateOid = GetTemplateOidFromCertExtension(Extension);
                    FoundTemplate = GetAll().Where(p => p.Version > 1)
                                            .FirstOrDefault(p => p.Oid.Matches(templateOid));

                    if (FoundTemplate == null)
                    {
                        throw new CertificateTemplateOidNotFoundException(templateOid);
                    }
                    PropertyCopier<ADCertificateTemplate, ADCertificateTemplate>.Copy(FoundTemplate, this);
                    return;
                }
            }

            throw new CertificateTemplateOidNotFoundException();
        }

        private void SetFieldsFromDirectoryObject(bool throwIfNotFound)
        {
            if (IsValid)
            {
                try
                {
                    Version = Convert.ToInt32(DirEntry.Properties[PropertyIndex.Version].Value);
                    ExtendedKeyUsages = ExtendedKeyUsage.GetEKUs(DirEntry);
                    KeyUsages = KeyUsage.GetKeyUsages((byte[])DirEntry.Properties[PropertyIndex.KeyUsage].Value);
                    RASignaturesRequired = (int)DirEntry.Properties[PropertyIndex.RASignaturesRequired].Value;
                    MinimumKeySize = (int)DirEntry.Properties[PropertyIndex.MinimumKeySize].Value;
                    Oid = DirEntry.Properties[PropertyIndex.OID].Value.ToString();
                    ValidityPeriod = ((byte[])DirEntry.Properties[PropertyIndex.ValidityPeriod].Value).ToTimeSpan();
                    PrivateKeyFlags = (int)DirEntry.Properties[PropertyIndex.PrivateKeyFlags].Value;
                }
                catch(Exception ex)
                {
                    CaughtEx = ex;
                    IsValid = false;
                }
            }
            if (!IsValid && throwIfNotFound)
            {
                throw new CertificateTemplateNotFoundException(CaughtEx);
            }
        }

        private void GetAccessRules()
        {
            try
            {
                ActiveDirectorySecurity Sec = DirEntry.ObjectSecurity;
                foreach (ActiveDirectoryAccessRule ADRule in Sec.GetAccessRules(true, true, typeof(NTAccount)))
                {
                    ADCertificateTemplateAccessRule CurrRule = new ADCertificateTemplateAccessRule(ADRule);

                    if (AccessRules.FirstOrDefault(p => p.Identity.Matches(CurrRule.Identity)) == null)
                    {
                        AccessRules.Add(CurrRule);
                    }
                    else
                    {
                        AccessRules.ForEach(p => p.MergeIf(CurrRule));
                    }
                }
            }
            catch (Exception ex)
            {
                throw new CertificateTemplateAccessRuleException(this, ex);
            }
        }

        /// <summary>
        /// Loads all certificate templates contained in the Active Directory forest
        /// </summary>
        /// <param name="refreshIfCached">If true, list will be generated from AD even if there is already a cached list. Default is false</param>
        /// <returns>A list of ADCertificateTemplate objects</returns>
        public static List<ADCertificateTemplate> GetAll(bool refreshIfCached = false)
        {
            if (!loadedAllTemplates | refreshIfCached)
            {
                GetAllWorker();
            }

            return all;
        }

        private static void GetAllWorker()
        {
            all = new List<ADCertificateTemplate>();
            ADCertificateTemplate Template;

            using (DirectoryEntry TemplatesContainer = new DirectoryEntry(LdapUrls.CertificateTemplatesContainer))
            {
                foreach(DirectoryEntry TemplateEntry in TemplatesContainer.Children)
                {
                    try
                    {
                        Template = new ADCertificateTemplate(TemplateEntry, throwIfNotFound: false);
                        if (Template.IsValid)
                        {
                            all.Add(Template);
                        }
                    }
                    catch (CertificateTemplateNotFoundException)
                    {
                        //This directory entry is not a certificate template object.
                    }
                }
            }

            loadedAllTemplates = true;
        }

        private static string GetTemplateOidFromCertExtension(X509Extension Extention)
        {
            AsnEncodedData asnData = new AsnEncodedData(Extention.Oid, Extention.RawData);
            string templateInfo = asnData.Format(true);
            return templateInfo.Split(new string[] { @"Template=" }, StringSplitOptions.None)[1].Split('\r')[0];
        }
    }
}
