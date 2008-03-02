<%@page import="org.owasp.esapi.*"%>

<%
	User user = ESAPI.authenticator().getCurrentUser();
	Logger logger = Logger.getLogger("ESAPI Test Application", getClass().getName());
	if ( user.isLoggedIn() ) {
%>
		<a href="controller?function=logout">Logout</a><br>
		Last Successful Login: <%=user.getLastLoginTime() %><br>
		Last Failed Login: <%=user.getLastFailedLoginTime() %><br>
<%
	} else {
%>
		<a href="controller">Login</a><br>
<%
	}
	if ( true ) { // AccessController.getInstance().isAuthorizedForFunction("admin") ) {
%>
		Current User: <%=user.getAccountName() %><br>
		Current Roles: <%=user.getRoles() %><br>
		Is First Request: <%=user.isFirstRequest() %><br>
		Last Host Name: <%=user.getLastHostAddress() %><br>
		Current Cookie: <script>document.write(document.cookie)</script>
<%
	}
%>
<HR>