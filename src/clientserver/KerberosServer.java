package clientserver;

import java.io.*;
import java.net.*;
import java.security.PrivilegedAction;
import java.util.Properties;
import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.Oid;
import sun.misc.BASE64Decoder;
 
public class KerberosServer {
 
  public static void main( String[] args) {
    try {
      // Setup up the Kerberos properties.
      Properties props = new Properties();
      props.load( new FileInputStream( "server.properties"));
      System.setProperty( "sun.security.krb5.debug", "true");
      System.setProperty( "java.security.krb5.realm", props.getProperty( "realm"));
      System.setProperty( "java.security.krb5.kdc", props.getProperty( "kdc"));
      System.setProperty( "java.security.auth.login.config", "jaas.conf");
      System.setProperty( "javax.security.auth.useSubjectCredsOnly", "true");
      String password = props.getProperty( "service.password");
      // Oid mechanism = use Kerberos V5 as the security mechanism.
      krb5Oid = new Oid( "1.2.840.113554.1.2.2");
      KerberosServer server = new KerberosServer();
      // Login to the KDC.
      server.login( password);
      ServerSocket s = new ServerSocket(7777);
      while (true) {
        Socket s2 = s.accept();
        BufferedReader is = new BufferedReader(new InputStreamReader(s2.getInputStream()));
        StringBuffer buffer = new StringBuffer();
        String str = null;
        while ((str = is.readLine()) != null) {
          buffer.append( str + "\n");
//          System.out.println("ticket = " + str);
        }
        is.close();

        @SuppressWarnings("restriction")
		BASE64Decoder decoder = new BASE64Decoder();
        @SuppressWarnings("restriction")
		String clientName = server.acceptSecurityContext(decoder.decodeBuffer( buffer.toString()));
        System.out.println( "\nSecurity context successfully initialised!");
        System.out.println( "\nHello World " + clientName + "!");
      }
    }
    catch (Exception e) {
      e.printStackTrace();
    }
  }
 
  private static Oid krb5Oid;
 
  private Subject subject;
 
  // Authenticate against the KDC using JAAS.
  private void login( String password) throws LoginException {
    LoginContext loginCtx = null;
    // "Client" references the JAAS configuration in the jaas.conf file.
    loginCtx = new LoginContext( "Server",new LoginCallbackHandler( password));
    loginCtx.login();
    this.subject = loginCtx.getSubject();
  }
 
  private String acceptSecurityContext( final byte[] serviceTicket)
      throws GSSException {
    krb5Oid = new Oid( "1.2.840.113554.1.2.2");
 
    return Subject.doAs( subject, new PrivilegedAction<String>() {
      public String run() {
        try {
          // Identify the server that communications are being made to.
          GSSManager manager = GSSManager.getInstance();
          GSSContext context = manager.createContext( (GSSCredential) null);
          context.acceptSecContext( serviceTicket, 0, serviceTicket.length);
          return context.getSrcName().toString() + " has connected to the " + context.getTargName() + " service " + context.getLifetime();
        }
        catch ( Exception e) {
          e.printStackTrace();
          return null;
        }
      }
    });
  }
  
  public boolean validateTicket(String ticket) {
	  try { Properties props = new Properties();
      props.load( new FileInputStream( "C:\\Users\\Administrator\\workspace\\KerberosSeurity\\server.properties"));
      System.setProperty( "sun.security.krb5.debug", "false");
      System.setProperty( "java.security.krb5.realm", props.getProperty( "realm"));
      System.setProperty( "java.security.krb5.kdc", props.getProperty( "kdc"));
      System.setProperty( "java.security.auth.login.config", "C:\\Users\\Administrator\\workspace\\KerberosSeurity\\jaas.conf");
      System.setProperty( "javax.security.auth.useSubjectCredsOnly", "true");
      String password = props.getProperty( "service.password");
      // Oid mechanism = use Kerberos V5 as the security mechanism.
      krb5Oid = new Oid( "1.2.840.113554.1.2.2");
      KerberosServer server = new KerberosServer();
      // Login to the KDC.
      server.login( password);
//      ServerSocket s = new ServerSocket(7777);
//      while (true) {
//        Socket s2 = s.accept();
//        BufferedReader is = new BufferedReader(new InputStreamReader(s2.getInputStream()));
//        StringBuffer buffer = new StringBuffer();
//        String str = null;
//        while ((str = is.readLine()) != null) {
//          buffer.append( str + "\n");
//          System.out.println("ticket = " + str);
//        }
//        is.close();

        @SuppressWarnings("restriction")
		BASE64Decoder decoder = new BASE64Decoder();
        
        @SuppressWarnings("restriction")
//		String clientName = server.acceptSecurityContext(decoder.decodeBuffer( buffer.toString()));
		String clientName = server.acceptSecurityContext(decoder.decodeBuffer(ticket.toString()));
        System.out.println( "\nSecurity context successfully initialised!");
        System.out.println( "\nHello World " + clientName + "!");
        return true;
//      }
	     
	    }
	    catch (Exception e) {
	      e.printStackTrace();
	      return false;
	    }
	  }
}