<%@ Control Language="C#" AutoEventWireup="false" Inherits="DNN.OpenId.Cognito.Login" CodeBehind="Login.ascx.cs" %>

<%@ Register TagPrefix="dnn" Assembly="DotNetNuke" Namespace="DotNetNuke.UI.WebControls"%>
<%@ Register TagPrefix="dnn" Namespace="DotNetNuke.Web.UI.WebControls.Internal" Assembly="DotNetNuke.Web" %>

<script type="text/javascript">

    var poolData = {
        UserPoolId: $("#txtPoolID").val(), // Your user pool id here
        ClientId: $("#txtClientID").val()
    };

    var userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);
    var cognitoUser;

    function signIn() {

        var username = $("#txtEmail").val();
        var password = $("#txtPassword").val();

        var authenticationData = {
            Username: username,
            Password: password
        };

        var userData = {
            Username: username,
            Pool: userPool,
        };

        var authenticationDetails = new AmazonCognitoIdentity.AuthenticationDetails(
            authenticationData
        );

        console.log("--------Authenticate --- " + username + ", UserPool:" + userPool);

        cognitoUser = new AmazonCognitoIdentity.CognitoUser(userData);

        //cognitoUser.setAuthenticationFlowType('CUSTOM_AUTH');

        cognitoUser.authenticateUser(authenticationDetails, {
            onSuccess: function (result) {
                var idToken = result.getIdToken().getJwtToken();
                var accessToken = result.getAccessToken().getJwtToken();

                $("#idToken").html('<b>ID Token</b><br>' + JSON.stringify(parseJwt(idToken), null, 2));
                $("#accessToken").html('<b>Access Token</b><br>' + JSON.stringify(parseJwt(accessToken), null, 2));
                console.log("AccessToken:" + accessToken);
            },

            onFailure: function (err) {
                alert(err.message || JSON.stringify(err));
            },

            totpRequired: function (codeDeliveryDetails) {
                console.log("mfaRequired");
                console.log(codeDeliveryDetails);
                var verificationCode = prompt('Please input second factor code', '');
                cognitoUser.sendMFACode(verificationCode, this, 'SOFTWARE_TOKEN_MFA');
            },
        });
    }

</script>



<div class="dnnForm dnnLoginService dnnClear">
    <div class="dnnFormItem">
        <asp:Label runat="server" CssClass="dnnFormMessage dnnFormInfo" style="margin-top:20px" ID="lblMessage"></asp:Label>
    </div>    
    <div class="dnnFormItem" runat="server" id="divEmail">
        <div class="dnnLabel">
            <asp:label id="lblEmail" AssociatedControlID="txtEmail" Text="Email:" runat="server" CssClass="dnnFormLabel" />
        </div>        
        <asp:textbox id="txtEmail" runat="server" />
    </div>
    <div class="dnnFormItem" runat="server" id="divUsername">
        <div class="dnnLabel">
            <asp:label id="lblUsername" AssociatedControlID="txtUsername" runat="server" Text="Username:" CssClass="dnnFormLabel" ViewStateMode="Disabled" />
        </div>
        <asp:textbox id="txtUsername" runat="server" />
    </div>
    <div class="dnnFormItem" runat="server" id="divPassword">
        <div class="dnnLabel">
            <asp:label id="lblPassword" AssociatedControlID="txtPassword" runat="server" Text="Password:" CssClass="dnnFormLabel" ViewStateMode="Disabled" />
        </div>
        <asp:textbox id="txtPassword" textmode="Password" runat="server" />
    </div>
    <div class="dnnFormItem">
        <asp:label id="lblLoginRememberMe" runat="server" CssClass="dnnFormLabel"  />
        <span class="dnnLoginRememberMe"><asp:checkbox id="chkCookie" resourcekey="Remember" runat="server" />Remember Login</span>
    </div>
    <div class="dnnFormItem">
        <asp:Label runat="server" CssClass="dnnFormMessage dnnFormError" ID="lblErrorMessage"></asp:Label>
    </div>    
    <div class="dnnFormItem">
        <asp:label id="lblempty" runat="server" CssClass="dnnFormLabel" />
        <asp:Button runat="server" ID="btnLogin" Text="Login" cssclass="dnnPrimaryAction" CausesValidation="false" />
        <asp:HyperLink id="cancelLink" runat="server" CssClass="dnnSecondaryAction" resourcekey="cmdCancel" CausesValidation="false" />        
    </div>
    
</div>


<asp:HiddenField runat="server" ID="txtPoolID"></asp:HiddenField>
<asp:HiddenField runat="server" ID="txtClientID"></asp:HiddenField>
<input type="hidden" id="hdnServerCodeExecuted" runat="server" />


<script type="text/javascript">
    window.onload = function () {
        var serverCodeExecuted = document.getElementById('<%= hdnServerCodeExecuted.ClientID %>').value;
        if (serverCodeExecuted === "true") {
            signIn();
        }
    };
</script>


