<%@ Control Language="C#" AutoEventWireup="false" Inherits="DNN.OpenId.Cognito.Login, DNN.OpenId.Cognito" CodeBehind="Login.ascx.cs" %>

<%@ Register TagPrefix="dnn" Namespace="DotNetNuke.UI.WebControls" Assembly="DotNetNuke" %>

<script type="text/javascript">
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
	.cognitoLabel{
		display: inline-block;
		text-align: right;
		float: left;
        position: relative;
        width: 32.075%;
        padding-right: 20px;
        margin-right: 18px;
        overflow: visible;
        text-align: right;
        font-weight: 700;
	}
	.cognitoTextbox{
		display: inline-block;
		text-align: left;
		float: right;
        margin-right: 100px;
	}

    .cognitoHeading { clear: both; margin-left: 15px;}
    .cognitoParagraph { margin-left: 15px; margin-right: 15px;}
</style>

<h3 class="cognitoHeading">OpenID - Cognito Configuration</h3>
<div class="dnnFormItem">
    <asp:Label class="cognitoLabel" ID="lblEmail" runat="server" Text="Email:" />
    <asp:TextBox class="cognitoTextbox" runat="server" ID="txtEmail"></asp:TextBox>
</div>
<div class="dnnFormItem">
    <asp:Label class="cognitoLabel" ID="lblPassword" runat="server" Text="Password:" />
    <asp:TextBox class="cognitoTextbox" runat="server" ID="txtPassword"></asp:TextBox>
</div>
<div class="dnnFormItem">
    <asp:Label class="cognitoLabel" ID="lblUsername" runat="server" Text="Username:" />
    <asp:TextBox class="cognitoTextbox" runat="server" ID="txtUsername"></asp:TextBox>
</div>

<div class="dnnFormItem">
    <asp:Button runat="server" ID="btnLogin" Text="Login" />
</div>





