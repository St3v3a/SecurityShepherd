<%@ page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"
	language="java" import="utils.*" errorPage=""%>
<%@ page import="java.util.Locale, java.util.ResourceBundle"%>
<%
/**
 * <br/><br/>
 * This file is part of the Security Shepherd Project.
 * 
 * The Security Shepherd project is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.<br/>
 * 
 * The Security Shepherd project is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.<br/>
 * 
 * You should have received a copy of the GNU General Public License
 * along with the Security Shepherd project.  If not, see <http://www.gnu.org/licenses/>. 
 *
 * @author Mark Denihan
 */
//No Quotes In level Name
String levelName = "Insecure Crypto Storage Challenge 4";
//Alphanumeric Only
String levelHash = "b927fc4d8c9f70a78f8b6fc46a0cc18533a88b2363054a1f391fe855954d12f9";


//Translation Stuff
Locale locale = new Locale(Validate.validateLanguage(request.getSession()));
ResourceBundle bundle = ResourceBundle.getBundle("i18n.challenges.insecureCryptoStorage.insecureCryptoStorage", locale);
//Used more than once translations
String i18nLevelName = bundle.getString("insecureCryptoStorage.4.challengename");

ShepherdLogManager.logEvent(request.getRemoteAddr(), request.getHeader("X-Forwarded-For"), levelName + " Accessed");
if (request.getSession() != null)
{
	HttpSession ses = request.getSession();
	//Getting CSRF Token from client
	Cookie tokenCookie = null;
	try
	{
		tokenCookie = Validate.getToken(request.getCookies());
	}
	catch(Exception htmlE)
	{
		ShepherdLogManager.logEvent(request.getRemoteAddr(), request.getHeader("X-Forwarded-For"), levelName +".jsp: tokenCookie Error:" + htmlE.toString());
	}
	// validateSession ensures a valid session, and valid role credentials
	// If tokenCookie == null, then the page is not going to continue loading
	if (Validate.validateSession(ses) && tokenCookie != null)
	{
		ShepherdLogManager.logEvent(request.getRemoteAddr(), request.getHeader("X-Forwarded-For"), levelName + " has been accessed by " + ses.getAttribute("userName").toString(), ses.getAttribute("userName"));
%>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="content-type" content="text/html; charset=utf-8" />
<title>Security Shepherd - <%= i18nLevelName %></title>
<link href="../css/lessonCss/theCss.css" rel="stylesheet"
	type="text/css" media="screen" />

</head>
<body>
	<script type="text/javascript" src="../js/jquery.js"></script>
	<script type="text/javascript"
		src="../js/clipboard-js/clipboard.min.js"></script>
	<script type="text/javascript" src="../js/clipboard-js/tooltips.js"></script>
	<script type="text/javascript"
		src="../js/clipboard-js/clipboard-events.js"></script>
	<div id="contentDiv">
		<h2 class="title"><%= i18nLevelName %></h2>
		<p>
			<%= bundle.getString("insecureCryptoStorage.4.whatToDo") %>
			<br /> <br />
		<h3 class="title"><%= bundle.getString("insecureCryptoStorage.4.shop") %></h3>
		<p><%= bundle.getString("insecureCryptoStorage.4.shop.message.1") %>
			<a>PleaseTakeAFruit</a>
			<%= bundle.getString("insecureCryptoStorage.4.shop.message.2") %>
			<a>FruitForFree</a>
			<%= bundle.getString("insecureCryptoStorage.4.shop.message.3") %></p>
		<br /> <br />
		<form id="leForm" action="javascript:;">
			<table>
				<!-- Header -->
				<tr>
					<th><%= bundle.getString("insecureCryptoStorage.4.shop.picture") %></th>
					<th><%= bundle.getString("insecureCryptoStorage.4.shop.cost") %></th>
					<th><%= bundle.getString("insecureCryptoStorage.4.shop.quantity") %></th>
				</tr>
				<!-- Apple Row -->
				<tr>
					<td><img width="50px" height="50px"
						src="<%= levelHash %>/apple.jpg" /></td>
					<td>$45</td>
					<td><input type="text" style="width: 50px" value="0"
						id="numberOfApples" autocomplete="off" />
				</tr>
				<!-- Banana Row -->
				<tr>
					<td><img width="50px" height="50px"
						src="<%= levelHash %>/banana.jpg" /></td>
					<td>$15</td>
					<td><input type="text" style="width: 50px" value="0"
						id="numberOfBananas" autocomplete="off" />
				</tr>
				<!-- Oranges Row -->
				<tr>
					<td><img width="50px" height="50px"
						src="<%= levelHash %>/orange.jpg" /></td>
					<td>$3000</td>
					<td><input type="text" style="width: 50px" value="0"
						id="numberOfOranges" autocomplete="off" />
				</tr>
				<!-- Pineapples Row -->
				<tr>
					<td><img width="50px" height="50px"
						src="<%= levelHash %>/pineapple.png" /></td>
					<td>$30</td>
					<td><input type="text" style="width: 50px" value="0"
						id="numberOfPineapples" autocomplete="off" />
				</tr>
			</table>
			<p><%= bundle.getString("insecureCryptoStorage.4.shop.howToShop") %></p>
			<table>
				<tr>
					<td><%= bundle.getString("insecureCryptoStorage.4.shop.couponCode") %></td>
					<td><input type="text" id="couponCode" autocomplete="off" /></td>
				</tr>
				<tr>
					<td colspons=2>
						<div id="submitButton">
							<input type="submit"
								value="<%= bundle.getString("insecureCryptoStorage.4.shop.submit") %>" />
						</div>
						<p style="display: none;" id="loadingSign"><%= bundle.getString("insecureCryptoStorage.loading") %></p>
					</td>
				</tr>
			</table>
		</form>

		<div id="resultsDiv"></div>
		</p>
	</div>
	<script>
			$("#leForm").submit(function(){
				var thePineappleAmount = $("#numberOfPineapples").val();
				var theOrangeAmount = $("#numberOfOranges").val();
				var theAppleAmount = $("#numberOfApples").val();
				var theBananaAmount = $("#numberOfBananas").val();
				var theCouponCode = $("#couponCode").val();
				$("#submitButton").hide("fast");
				$("#loadingSign").show("slow");
				$("#resultsDiv").hide("slow", function(){
					var ajaxCall = $.ajax({
						type: "POST",
						url: "<%= levelHash %>",
						data: {
							pineappleAmount: thePineappleAmount, 
							orangeAmount: theOrangeAmount,
							appleAmount: theAppleAmount, 
							bananaAmount: theBananaAmount,
							couponCode: theCouponCode
						},
						async: false
					});
					if(ajaxCall.status == 200)
					{
						$("#resultsDiv").html(ajaxCall.responseText);
					}
					else
					{
						$("#resultsDiv").html("<p> <%= bundle.getString("insecureCryptoStorage.errorOccurred") %>: " + ajaxCall.status + " " + ajaxCall.statusText + "</p>");
					}
					$("#resultsDiv").show("slow", function(){
						$("#loadingSign").hide("fast", function(){
							$("#submitButton").show("slow");
						});
					});
				});
			});
		</script>
	<% if(Analytics.googleAnalyticsOn) { %><%= Analytics.googleAnalyticsScript %>
	<% } %>
</body>
</html>
<%
	}
	else
	{
		response.sendRedirect("../loggedOutSheep.html");
	}
}
else
{
	response.sendRedirect("../loggedOutSheep.html");
}
%>