<%@ Control Language="C#" AutoEventWireup="false" Inherits="DNN.OpenId.Cognito.Settings" CodeBehind="Settings.ascx.cs" %>

<%@ Register TagPrefix="dnn" Namespace="DotNetNuke.UI.WebControls" Assembly="DotNetNuke" %>


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
    <asp:label class="cognitoLabel" id="lblEnabled" runat="server" Text="Enabled:"></asp:label>
    <asp:CheckBox class="cognitoTextbox" Checked="true" runat="server" ID="chkEnabled"></asp:CheckBox>
</div>
<div class="dnnFormItem">
    <asp:Label class="cognitoLabel" ID="lblApiKey" runat="server" Text="API Key:" />
    <asp:TextBox class="cognitoTextbox" runat="server" ID="txtApiKey"></asp:TextBox>
</div>
<div class="dnnFormItem">
    <asp:Label class="cognitoLabel" ID="lblApiSecret" runat="server" Text="API Secret:" />
    <asp:TextBox class="cognitoTextbox" runat="server" ID="txtApiSecret"></asp:TextBox>
</div>
<div class="dnnFormItem">
    <asp:Label class="cognitoLabel" ID="lblIAMUserAccessKey" runat="server" Text="IAM User Access Key:" />
    <asp:TextBox class="cognitoTextbox" runat="server" ID="txtIAMUserAccessKey"></asp:TextBox>
</div>
<div class="dnnFormItem">
    <asp:Label class="cognitoLabel" ID="lblIAMUserSecretKey" runat="server" Text="IAM User Access Key:" />
    <asp:TextBox class="cognitoTextbox" runat="server" ID="txtIAMUserSecretKey"></asp:TextBox>
</div>
<div class="dnnFormItem">
    <asp:Label class="cognitoLabel" ID="lblAppUsername" runat="server" Text="App Username:" />
    <asp:TextBox class="cognitoTextbox" runat="server" ID="txtAppUsername"></asp:TextBox>
</div>
<div class="dnnFormItem">
    <asp:Label class="cognitoLabel" ID="lblCognitoPoolID" runat="server" Text="Cognito Pool ID:" />
    <asp:TextBox class="cognitoTextbox" runat="server" ID="txtCognitoPoolID"></asp:TextBox>
</div>
<div class="dnnFormItem">
    <asp:Label class="cognitoLabel" ID="lblRedirectUrl" runat="server" Text="Redirect URL:" />
    <asp:TextBox class="cognitoTextbox" runat="server" ID="txtRedirectURL"></asp:TextBox>
</div>
<div class="dnnFormItem">
    <asp:Label class="cognitoLabel" ID="lblLoginURL" runat="server" Text="Login URL:" />
    <asp:TextBox class="cognitoTextbox" runat="server" ID="txtLoginURL"></asp:TextBox>
</div>
<div class="dnnFormItem">
    <asp:label class="cognitoLabel" id="lblUseHostedUI" runat="server" Text="Use Hosted UI:"></asp:label>
    <asp:CheckBox class="cognitoTextbox" Checked="true" runat="server" ID="chkHostedUI"></asp:CheckBox>
</div>
<div class="dnnFormItem">
    <asp:Label class="cognitoLabel" ID="lblCognitoDomain" runat="server" Text="Cognito Domain:" />
    <asp:TextBox class="cognitoTextbox" runat="server" ID="txtCognitoDomain"></asp:TextBox>
</div>
<div class="dnnFormItem">
    <asp:Label class="cognitoLabel" ID="lblLoginMessage" runat="server" Text="Login Message:" />
    <asp:TextBox class="cognitoTextbox" runat="server" ID="txtLoginMessage"></asp:TextBox>
</div>
<div class="dnnFormItem">
    <asp:label class="cognitoLabel" id="lblHandleSSO" runat="server" Text="Handle SSO:"></asp:label>
    <asp:CheckBox class="cognitoTextbox" Checked="true" runat="server" ID="chkHandleSSO"></asp:CheckBox>
</div>





