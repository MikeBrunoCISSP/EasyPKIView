using System;
using System.DirectoryServices;

namespace EasyPKIView
{
    /// <summary>
    /// Describes an entry in the Public Key Services container of Active Directory
    /// </summary>
    public class ADCSDirectoryEntry
    {
        internal DirectoryEntry DirEntry;
        internal bool IsValid = false;

        /// <summary>
        /// The Name attribute of the directory entry
        /// </summary>
        public string Name { get; internal set; }

        /// <summary>
        /// The Display name attribute of the directory entry
        /// </summary>
        public string DisplayName { get; internal set; }

        /// <summary>
        /// The Distinguished Name attribute of the directory entry
        /// </summary>
        public string DistinguishedName { get; internal set; }

        /// <summary>
        /// Indicates when the directory entry was created
        /// </summary>
        public DateTime WhenCreated { get; internal set; }

        /// <summary>
        /// Indicates when the directory entry was last modified
        /// </summary>
        public DateTime WhenChanged { get; internal set; }

        /// <summary>
        /// The GUID of the directory entry
        /// </summary>
        public Guid ObjectGuid { get; internal set; }

        /// <summary>
        /// ADCSDirectoryEntry default constructor (do not use)
        /// </summary>
        public ADCSDirectoryEntry()
        { }

        /// <summary>
        /// ADCSDirectoryEntry Constructor 1
        /// </summary>
        /// <param name="Entry">Directory Entry pointing to the desired directory object</param>
        /// <param name="expectedObjectClass">Indicates the expected object class for the directory entry (either a certificate template or a CA)</param>
        public ADCSDirectoryEntry(DirectoryEntry Entry, string expectedObjectClass)
        {
            DirEntry = Entry;
            SetFieldsFromDirectoryEntry(expectedObjectClass);
        }

        /// <summary>
        /// ADCSDirectoryEntry Constructor 2
        /// </summary>
        /// <param name="ldapURL">The fully-qualified LDAP URL to the desired object</param>
        /// <param name="expectedObjectClass">Indicates the expected object class for the directory entry (either a certificate template or a CA)</param>
        public ADCSDirectoryEntry(string ldapURL, string expectedObjectClass)
            : this(new DirectoryEntry(ldapURL), expectedObjectClass)
        { }

        private void SetFieldsFromDirectoryEntry(string expectedObjectClass)
        {
            if (DirEntry == null)
            {
                return;
            }

            try
            {
                object[] objectClass = (object[])DirEntry.Properties[PropertyIndex.ObjectClass].Value;
                if (objectClass.Length < 2 || !objectClass[1].ToString().Matches(expectedObjectClass))
                {
                    return;
                }

                Name = DirEntry.Properties[PropertyIndex.Name].Value.ToString();
                DisplayName = DirEntry.Properties[PropertyIndex.DisplayName].Value.ToString();
                DistinguishedName = DirEntry.Properties[PropertyIndex.DistinguishedName].Value.ToString();
                ObjectGuid = new Guid((byte[])DirEntry.Properties[PropertyIndex.ObjectGUID].Value);
                WhenCreated = (DateTime)DirEntry.Properties[PropertyIndex.WhenCreated].Value;
                WhenChanged = (DateTime)DirEntry.Properties[PropertyIndex.WhenChanged].Value;

                IsValid = true;
            }
            catch (DirectoryServicesCOMException)
            {
                //Not valid
            }
        }
    }
}
