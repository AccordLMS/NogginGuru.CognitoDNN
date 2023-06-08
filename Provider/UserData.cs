using System;
using System.Runtime.Serialization;

namespace ProcsIT.Dnn.AuthServices.OpenIdConnect
{
    // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.5.1

    [DataContract]
    public class UserData
    {
        // service+sub
        [DataMember(Name = "id")]
        public string Id { get; set; }

        [DataMember(Name = "name")]
        public string Name { get; set; }

        [DataMember(Name = "given_name")]
        public string GivenName { get; set; }

        [DataMember(Name = "family_name")]
        public string FamilyName { get; set; }

        [DataMember(Name = "middle_name")]
        public string MiddleName { get; set; }

        [DataMember(Name = "nickname")]
        public string NickName { get; set; }

        [DataMember(Name = "preferred_username")]
        public string PreferredUserName { get; set; }

        [DataMember(Name = "profile")]
        public string Profile { get; set; }

        [DataMember(Name = "picture")]
        public string Picture { get; set; }

        [DataMember(Name = "website")]
        public string Website { get; set; }

        [DataMember(Name = "email")]
        public string Email { get; set; }

        [DataMember(Name = "email_verified")]
        public string EmailVerified { get; set; }

        [DataMember(Name = "gender")]
        public string Gender { get; set; }

        [DataMember(Name = "birthdate")]
        public virtual string BirthDate { get; set; }

        [DataMember(Name = "zoneinfo")]
        public virtual string ZoneInfo { get; set; }

        [DataMember(Name = "locale")]
        public virtual string Locale { get; set; }

        [DataMember(Name = "phone_number")]
        public virtual string PhoneNumber { get; set; }

        [DataMember(Name = "phone_number_verified")]
        public virtual string PhoneNumberVerified { get; set; }

        [DataMember(Name = "updated_at")]
        public virtual string UpdatedAt { get; set; }

        [DataMember(Name = "username")]
        public virtual string Username { get; set; }


        // TODO:

        public virtual string DisplayName { get { return Name; } set { } }

        public virtual string FirstName
        {
            get
            {
                return (!string.IsNullOrEmpty(Name) && Name.IndexOf(" ", StringComparison.Ordinal) > 0) ? Name.Substring(0, Name.IndexOf(" ", StringComparison.Ordinal)) : String.Empty;
            }
            set { Name = value + " " + LastName; }
        }

        public virtual string LastName
        {
            get
            {
                return (!string.IsNullOrEmpty(Name) && Name.IndexOf(" ", StringComparison.Ordinal) > 0) ? Name.Substring(Name.IndexOf(" ", StringComparison.Ordinal) + 1) : Name;
            }
            set { Name = FirstName + " " + value; }

        }

    }
}