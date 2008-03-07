<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<html>
<head>
<title>Login</title>
</head>
<body>

	<%@include file="menu.jsp" %>

   	<FORM method="post" action="/ESAPITest/controller"><br>
		username: <INPUT name="username"><br>
		password: <INPUT type="password" name="password"><br>
		<BUTTON type='submit'>Login</BUTTON>
	</FORM>

</body>
