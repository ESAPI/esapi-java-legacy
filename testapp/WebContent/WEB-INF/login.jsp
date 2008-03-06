<%@ page language="java" contentType="text/html; charset=ISO-8859-1" pageEncoding="ISO-8859-1"%>
<html>
<head>
<title>Login</title>
</head>
<body>
<%@include file="menu.jsp" %>

<hr>
   	<FORM method="post" action="/ESAPITest/controller"><br>
		username: <INPUT name="username"><br>
		password: <INPUT type="password" name="password"><br>
		<BUTTON type='submit'>Login</BUTTON>
	</FORM>
</body>
