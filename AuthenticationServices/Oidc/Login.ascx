<%@ Control Language="C#" AutoEventWireup="true" CodeBehind="Login.ascx.cs" Inherits="ProcsIT.Dnn.Authentication.OpenIdConnect.Login" %>
<div class="container">
<ul class="buttonList">
    <li id="loginItem" runat="server" class="oidc" >
        <asp:LinkButton runat="server" ID="loginButton" CausesValidation="False">
            <span><%=LocalizeString("LoginOidc") %></span>
        </asp:LinkButton>
    </li>
</ul>
</div>
