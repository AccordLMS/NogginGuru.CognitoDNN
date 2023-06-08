<%@ Control Language="C#" AutoEventWireup="false" Inherits="DNN.OpenId.Cognito.Settings, DNN.OpenId.Cognito" CodeBehind="Settings.ascx.cs" %>

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
    <asp:Label class="cognitoLabel" ID="lblRedirectUrl" runat="server" Text="Redirect URL:" />
    <asp:TextBox class="cognitoTextbox" runat="server" ID="txtRedirectURL"></asp:TextBox>
</div>






