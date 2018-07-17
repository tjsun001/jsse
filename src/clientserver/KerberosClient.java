package clientserver;

import java.io.*;
import java.net.*;
import java.security.PrivilegedAction;
import java.util.Properties;
import javax.security.auth.Subject;
import javax.security.auth.login.*;
import org.ietf.jgss.*;
import sun.misc.BASE64Encoder;
import org.ietf.jgss.Oid;

public class KerberosClient {
	private static Oid krb5Oid;
	 
	  private Subject subject;
	  private byte[] serviceTicket;
	 
	  public static void main( String[] args) {
	    try {
	      // Setup up the Kerberos properties.
	      String path = "${Path}";
	      Properties props = new Properties();
	      props.load( new FileInputStream( "C:\\Users\\Administrator\\workspace\\KerberosSeurity\\client.properties"));
	      System.setProperty( "sun.security.krb5.debug", "false");
	      System.setProperty( "java.security.krb5.realm", props.getProperty( "realm")); 
	      System.setProperty( "java.security.krb5.kdc", props.getProperty( "kdc"));
	      System.setProperty( "java.security.auth.login.config", "C:\\Users\\Administrator\\workspace\\KerberosSeurity\\jaas.conf");
	      System.setProperty( "javax.security.auth.useSubjectCredsOnly", "true");
	      String username = props.getProperty( "client.principal.name");
	      String password = props.getProperty( "client.password");
	      String servicePrincipalName =	props.getProperty("service.principal.name");
	      // Oid mechanism = use Kerberos V5 as the security mechanism.
	      krb5Oid = new Oid( "1.2.840.113554.1.2.2");
	      KerberosClient client = new KerberosClient();
	      // Login to the KDC.
	      client.login( username, password);
	      // Request the service ticket.
	      client.initiateSecurityContext( servicePrincipalName);
	      // Write the ticket to disk for the server to read.
//	      encodeAndWriteTicketToDisk( client.serviceTicket, "./security.token");
//	      System.out.println( "Service ticket encoded to disk successfully");
	      
	      String tmp = encodeAndWriteTicketToDisk( client.serviceTicket, "./security.token");
	      System.out.println("ticket = " + tmp);
	      Socket s = new Socket("localhost",7777);
	      PrintWriter out = new PrintWriter(s.getOutputStream());   
	      out.println(tmp);
	      out.flush();
	      out.close();
	      System.exit(0);
	      
	      
	    }
	    catch ( LoginException e) {
	      e.printStackTrace();
	      System.err.println( "There was an error during the JAAS login");
	      System.exit( -1);
	    }
	    catch ( GSSException e) {
	      e.printStackTrace();
	      System.err.println( "There was an error during the security context initiation");
	      System.exit( -1);
	    }
	    catch ( IOException e) {
	      e.printStackTrace();
	      System.err.println( "There was an IO error");
	      System.exit( -1);
	    }
	  }
	 
	  public KerberosClient() {
	    super();
	  }
	  public String getKerberosTicket() {
		  try {
		      // Setup up the Kerberos properties.
		      Properties props = new Properties();
//		      String path = "${path}";
//		      props.load( new FileInputStream( "client.properties"));
		      props.load( new FileInputStream( "C:\\Users\\Administrator\\workspace\\KerberosSeurity\\client.properties"));
		      
		      System.setProperty( "sun.security.krb5.debug", "false");
		      System.setProperty( "java.security.krb5.realm", props.getProperty( "realm")); 
		      System.setProperty( "java.security.krb5.kdc", props.getProperty( "kdc"));
		      System.setProperty( "java.security.auth.login.config", "C:\\Users\\Administrator\\workspace\\KerberosSeurity\\jaas.conf");
		      System.setProperty( "javax.security.auth.useSubjectCredsOnly", "true");
		      String username = props.getProperty( "client.principal.name");
		      String password = props.getProperty( "client.password");
		      String servicePrincipalName =	props.getProperty("service.principal.name");
		      // Oid mechanism = use Kerberos V5 as the security mechanism.
		      krb5Oid = new Oid( "1.2.840.113554.1.2.2");
//		      KerberosClient client = new KerberosClient();
		      // Login to the KDC.
		      this.login( username, password);
		      // Request the service ticket.
		      this.initiateSecurityContext( servicePrincipalName);
		      // Write the ticket to disk for the server to read.
//		      encodeAndWriteTicketToDisk( this.serviceTicket, "./security.token");
//		      System.out.println( "Service ticket encoded to disk successfully");
		      
		      String encodedClientKerberosTicket = encodeAndWriteTicketToDisk( this.serviceTicket, "./security.token");
//		      System.out.println("ticket = " + encodedClientKerberosTicket);
//		      Socket s = new Socket("localhost",7777);
//		      PrintWriter out = new PrintWriter(s.getOutputStream());   
//		      out.println(encodedClientKerberosTicket);
//		      out.flush();
//		      out.close();
//		      System.exit(0);
		      return encodedClientKerberosTicket;
		      
		      
		    }
		    catch ( LoginException e) {
		      e.printStackTrace();
		      System.err.println( "There was an error during the JAAS login");
		      System.exit( -1);
		    }
		    catch ( GSSException e) {
		      e.printStackTrace();
		      System.err.println( "There was an error during the security context initiation");
		      System.exit( -1);
		    }
		    catch ( IOException e) {
		      e.printStackTrace();
		      System.err.println( "There was an IO error");
		      System.exit( -1);
		    }
		return null;
		  }
		  
	 
	  // Authenticate against the KDC using JAAS.
	  private void login( String username, String password) throws LoginException {
	    LoginContext loginCtx = null;
	    // "Client" references the JAAS configuration in the jaas.conf file.
	    loginCtx = new LoginContext( "Client",
	        new LoginCallbackHandler( username, password));
	    loginCtx.login();
	    this.subject = loginCtx.getSubject();
	  }
	 
	  // Begin the initiation of a security context with the target service.
	  private void initiateSecurityContext( String servicePrincipalName)
	      throws GSSException {
	    GSSManager manager = GSSManager.getInstance();
	    GSSName serverName = manager.createName( servicePrincipalName,
	        GSSName.NT_HOSTBASED_SERVICE);
	    final GSSContext context = manager.createContext( serverName, krb5Oid, null,
	        GSSContext.DEFAULT_LIFETIME);
	    // The GSS context initiation has to be performed as a privileged action.
	    this.serviceTicket = Subject.doAs( subject, new PrivilegedAction<byte[]>() {
	      public byte[] run() {
	        try {
	          byte[] token = new byte[0];
	          // This is a one pass context initialisation.
	          context.requestMutualAuth( false);
	          context.requestCredDeleg( false);
	          return context.initSecContext( token, 0, token.length);
	        }
	        catch ( GSSException e) {
	          e.printStackTrace();
	          return null;
	        }
	      }
	    });	 
	  }
	 
	  // Base64 encode the raw ticket and write it to the given file.
	  private static String encodeAndWriteTicketToDisk( byte[] ticket, String filepath)
	      throws IOException {
	    BASE64Encoder encoder = new BASE64Encoder();    
	    FileWriter writer = new FileWriter( new File( filepath));
	    String encodedToken = encoder.encode( ticket);
	    writer.write( encodedToken);
	    writer.close();
		return encodedToken;
	  }
	}
