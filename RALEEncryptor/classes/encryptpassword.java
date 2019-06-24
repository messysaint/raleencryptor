// Original code from  http://developer.iplanet.com/docs/technote/ldap/pass_sha.html

/*
 * Used to digest/hash userpassword (called by modifyUserPassword3.java)
 */
import java.security.MessageDigest; // http://www.javasoft.com/products/jdk/1.1/docs/api/java.security.MessageDigest.html
import javax.commerce.util.BASE64Encoder; // http://www.javasoft.com/products/commerce/ jecf.jar
import javax.commerce.util.BASE64Decoder; // An alternative: import util.BASE64Encoder; // http://professionals.com/~cmcmanis/java/encoders/
import java.io.*;

class encryptpassword {
    
    static String mySalt = null;
    static String password = null;
    static String config = null;
       
    public static void main(String[] args) throws java.io.IOException, java.security.NoSuchAlgorithmException {
                   
        if (args.length < 3) {            
            System.out.print( "usage: encryptpassword <salt> <password> <configurationFile>\n" );
            return;
        }                  
        
        mySalt = args[0];   
        password = args[1];   
        config = args[2];      
                                      	
       	//String digest = digestPassword();               
        String temp = readConfigFile( digestPassword() );     	            
           
        if( rewriteConfigFile( temp ) ) {
        	System.out.println( "Done ..." );
        } else {
        	System.out.println( "Error ..." );
        }                    
        
    }
    
    
    private static String readConfigFile( String digest ) {
    	
    	String configString = "";
    	DataInputStream in;
		String line = new String();
		File file = new File( config );
    	
    	if( file.exists() ) {
    		
    		try {            
            	in = new DataInputStream( new BufferedInputStream( new FileInputStream( file ) ) );
            	
            	while( (line = in.readLine())!= null ) {
            		
            		line = line.trim();
            		if( line.toLowerCase().startsWith( "password" ) ) {
            			String temp = line.substring( 0, line.indexOf( "=" ) + 1 );
            			configString += ( temp + ' ' + digest + '\n' );
            		} else {
            			configString += ( line + '\n' );
            		}
                	
            	}
				
				in.close();
        	} catch( IOException e) {
            	System.out.println("Error opening: " + file);
        	}

    		
    	}    	
    	
    	return configString;
    	
    }
    
    
    private static boolean rewriteConfigFile( String modified ) {
    	
    	boolean rvalue = false;
    	
    	File file = new File( config );
    	
    	try {
    		FileWriter fw = new FileWriter( file );    	
    		fw.write( modified, 0, modified.length() );    	
    		fw.close();
    		rvalue = true;
    	} catch( java.io.IOException ioe ) {
    		System.out.println( ioe.toString() );
    	}
    	
    	
    	return rvalue;
    	
    }
    
    
    private static String digestPassword() throws java.io.IOException, java.security.NoSuchAlgorithmException {
    	
    	MessageDigest sha = MessageDigest.getInstance("SHA-1");
                
        // generate static key
        //keyGenerator kgen = new keyGenerator();                
        byte[] salt = fromHex( mySalt ); 
        
        String label = "{SSHA}";
        BASE64Encoder base64 = new BASE64Encoder();
                                                 	
        sha.reset();
        sha.update( password.getBytes() );
        sha.update(salt);
        byte[] pwhash = sha.digest();
            
        return label + base64.encode( concatenate(pwhash, salt) );
        
    	
    }
    
    
    private static byte[] concatenate(byte[] l, byte[] r) {
        byte[] b = new byte [l.length + r.length];
        System.arraycopy(l, 0, b, 0, l.length);
        System.arraycopy(r, 0, b, l.length, r.length);
        return b;
    }
    
    private static byte[][] split(byte[] src, int n) {
        byte[] l, r;
        if (src.length <= n) {
            l = src;
            r = new byte[0];
        } else {
            l = new byte[n];
            r = new byte[src.length - n];
            System.arraycopy(src, 0, l, 0, n);
            System.arraycopy(src, n, r, 0, r.length);
        }
        byte[][] lr = {l, r};
        return lr;
    }
    
    private static String hexits = "0123456789abcdef";
    
    private static String toHex( byte[] block ) {
        StringBuffer buf = new StringBuffer();
        for ( int i = 0; i < block.length; ++i ) {
            buf.append( hexits.charAt( ( block[i] >>> 4 ) & 0xf ) );
            buf.append( hexits.charAt( block[i] & 0xf ) );
        }
        return buf + "";
    }
    
    private static byte[] fromHex( String s ) {
        s = s.toLowerCase();
        byte[] b = new byte [(s.length() + 1) / 2];
        int j = 0;
        int h;
        int nybble = -1;
        for (int i = 0; i < s.length(); ++i) {
            h = hexits.indexOf(s.charAt(i));
            if (h >= 0) {
                if (nybble < 0) {
                    nybble = h;
                } else {
                    b[j++] = (byte)((nybble << 4) + h);
                    nybble = -1;
                }
            }
        }
        if (nybble >= 0) {
            b[j++] = (byte)(nybble << 4);
        }
        if (j < b.length) {
            byte[] b2 = new byte [j];
            System.arraycopy(b, 0, b2, 0, j);
            b = b2;
        }
        return b;
    }
    
}
