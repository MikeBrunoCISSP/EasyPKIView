using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EasyPKIView
{
    /// <summary>
    /// Thrown if a new Extended Key Usage (EKU) is attempted to be established, but the new EKU contains a name or OID that already exists.
    /// </summary>
    public class ExtendedKeyUsageAlreadyExistsException : Exception
    {
        internal ExtendedKeyUsageAlreadyExistsException(string oid, string name)
            : base($"An extended key usage with the name {name} or object ID {oid} already exists in the supported collection")
        { }
    }

    /// <summary>
    /// Thrown if a certificate template cannot be found in Active Directory
    /// </summary>
    public class CertificateTemplateNotFoundException : Exception
    {
        internal CertificateTemplateNotFoundException(string name)
            : base($"A certificate template with the name \"{name}\" could not be found in the current Active Directory forest")
        { }

        internal CertificateTemplateNotFoundException(Exception innerException)
            : base(@"Exception encountered attempting to read the specified certificate template directory entry in the current Active Directory forest", innerException)
        { }

        internal CertificateTemplateNotFoundException()
            : base(@"The specified certificate template directory entry does not exist in the current Active Directory forest")
        { }
    }

    /// <summary>
    /// Thrown if a certificate template cannot be found by OID in the Active Directory
    /// </summary>
    public class CertificateTemplateOidNotFoundException : Exception
    {
        /// <summary>
        /// CertificateTemplateOidNotFoundException Constructor 1
        /// </summary>
        /// <param name="oid"></param>
        public CertificateTemplateOidNotFoundException(string oid)
            : base($"A certificate template with Oid {oid} was not found in the current Active Directory forest. It may exist in a different Active Directory forest or have been deleted from the current forest.")
        { }

        /// <summary>
        /// CertificateTemplateOidNotFoundException Constructor 2
        /// </summary>
        public CertificateTemplateOidNotFoundException()
            : base(@"The specified certificate does not contain the certificate template extension. It may not have been issued from a Microsoft Enterprise Certification Authority.")
        { }
    }

    /// <summary>
    /// Thrown if the access rules for a certificate template cannot be successfully retrieved from AD.
    /// </summary>
    public class CertificateTemplateAccessRuleException : Exception
    {
        /// <summary>
        /// CertificateTemplateAccessRuleException constructor
        /// </summary>
        /// <param name="Template">An ADCertificateTemplate object</param>
        /// <param name="ex">The exception that occured while doing the Access Rule check</param>
        public CertificateTemplateAccessRuleException(ADCertificateTemplate Template, Exception ex)
            : base($"An exception was encountered retrieving the access rules for certificate template {Template.Name} (OID: {Template.Oid})", ex)
        { }
    }
        

    /// <summary>
    /// Thrown if a Certification Authority cannot be found in the Active Directory
    /// </summary>
    public class CertificationAuthorityNotFoundException : Exception
    {
        internal CertificationAuthorityNotFoundException(string name)
            : base($"A certification authority enrollment services object with the name \"{name}\" could not be found in the current Active Directory forest")
        { }

        internal CertificationAuthorityNotFoundException(Exception innerException)
            : base(@"Exception encountered attempting to read the specified enrollment services directory entry in the current Active Directory forest", innerException)
        { }

        internal CertificationAuthorityNotFoundException()
            : base(@"The specified certification authority enrollment services directory entry does not exist in the current Active Directory forest")
        { }
    }
}
