<%@ Control Language="C#" AutoEventWireup="false" Inherits="DNN.OpenId.Cognito.Login" CodeBehind="Login.ascx.cs" %>

<%@ Register TagPrefix="dnn" Namespace="DotNetNuke.UI.WebControls" Assembly="DotNetNuke" %>

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

<style type="text/css">
    .dnnFormItem {
  clear: both;
  width: 100%;
  display: flex;
  align-items: center;
  position: relative;
  text-align: left;
}
	.cognitoLabel{
		border: 0;
        display: inline-block;
        max-width: 100%;
        margin-bottom: 5px;
        font-weight: 700;
        margin: 0;
        padding: 0;
        vertical-align: baseline;
	}
	.cognitoTextbox{
		width: 200px;
        min-width: 200px;
        margin-bottom: 5px;
        max-width: 445px;
        padding: 8px;
        background: #ffffff;
        border: 1px solid #c9c9c9;
        border-radius: 3px;
        font-size: 12px;
        color: #333;
	}

    .cognitoHeading { clear: both; margin-left: 15px;}
    .cognitoParagraph { margin-left: 15px; margin-right: 15px;}
</style>

<asp:Label runat="server" ID="lblMessage"></asp:Label>
<div class="dnnFormItem" runat="server" id="divEmail">
    <asp:Label class="cognitoLabel" ID="lblEmail" runat="server" Text="Email:" />
    <asp:TextBox class="cognitoTextbox" runat="server" ID="txtEmail"></asp:TextBox>
</div>
<div class="dnnFormItem" runat="server" id="divUsername">
    <asp:Label class="cognitoLabel" ID="lblUsername" runat="server" Text="Username:" />
    <asp:TextBox class="cognitoTextbox" runat="server" ID="txtUsername"></asp:TextBox>
</div>
<div class="dnnFormItem" runat="server" id="divPassword">
    <asp:Label class="cognitoLabel" ID="lblPassword" runat="server" Text="Password:" />
    <asp:TextBox class="cognitoTextbox" runat="server" ID="txtPassword"></asp:TextBox>
</div>

<asp:Label runat="server" ID="lblErrorMessage"></asp:Label>

<div class="dnnFormItem">
    <asp:Button runat="server" ID="btnLogin" Text="Login" />
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


