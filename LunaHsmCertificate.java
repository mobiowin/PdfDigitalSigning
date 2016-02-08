/* ----- 
  File LunaHsmCertificate.java
	Owner@File : Raman 
	Date : 06/12/2014  ---------*/

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.Key;
import java.util.HashMap;
import java.util.Properties;
import java.io.*;

import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.MakeSignature.CryptoStandard;
import com.safenetinc.luna.provider.LunaCertificateX509;

class LunaHsmCertificate
{

	static String hsmLunaPwd;
    static String hsmLunaSlot;
	static String hsmPkAlias;
	static String hsmLunaLabel;
	static String hsmProvider;
	static Properties properties;
	


	public static HashMap<String,Object> getLunaSignDetails()
	{
		KeyStore lunaKeyStore = null;
		LunaCertificateX509[] certChain = null;
		java.security.Provider provider = new com.safenetinc.luna.provider.LunaProvider();
		HashMap<String,Object> digiSignParamsMap = null;

		try 
		{
			intitalizeConst();

			ByteArrayInputStream is1 = new ByteArrayInputStream((hsmLunaSlot).getBytes());

			System.out.println("Test is : " + is1);

			Security.addProvider(provider);
			lunaKeyStore = KeyStore.getInstance(hsmProvider);
			lunaKeyStore.load(is1, hsmLunaPwd.toCharArray());


			PrivateKey privateKey = (PrivateKey) lunaKeyStore.getKey(hsmPkAlias, hsmLunaPwd.toCharArray());

			System.out.println("Private key is : " + privateKey);

			Certificate cert = lunaKeyStore.getCertificate(hsmLunaLabel);
			
			System.out.println("Certification is : " + cert.getType());
				
			certChain = new LunaCertificateX509[1];
			certChain[0] = (LunaCertificateX509)cert;
				
			System.out.println("Certification is : " + certChain);

			digiSignParamsMap = new HashMap<String,Object>();

			digiSignParamsMap.put(LunaHsmKeyConstants.LUAN_CERT_CHAIN,certChain);
			digiSignParamsMap.put(LunaHsmKeyConstants.LUAN_PRIVATE_KEY,privateKey);
			digiSignParamsMap.put(LunaHsmKeyConstants.LUAN_DIGEST_ALGO,DigestAlgorithms.SHA256);
			digiSignParamsMap.put(LunaHsmKeyConstants.HSM_PROVIDER_NAME, provider.getName());
			digiSignParamsMap.put(LunaHsmKeyConstants.HSM_CRYPTO_STANDRAD,CryptoStandard.CMS);
			digiSignParamsMap.put(LunaHsmKeyConstants.HSM_REASON,LunaHsmValueConstants.HSM_REASON);
			digiSignParamsMap.put(LunaHsmKeyConstants.HSM_LOCATION,LunaHsmValueConstants.HSM_LOCATION);

			System.out.println("Digital Sign ParamsMap is : " + digiSignParamsMap.toString());

			return digiSignParamsMap;
		
		}
		catch (KeyStoreException kse) 
		{
			System.out.println("Unable to create keystore object");
			System.exit(-1);
			return digiSignParamsMap;
		}
		catch (NoSuchAlgorithmException nsae) 
		{
			System.out.println("Unexpected NoSuchAlgorithmException while loading keystore");
			System.exit(-1);
			return digiSignParamsMap;
		}
		catch (CertificateException e) 
		{
			System.out.println("Unexpected CertificateException while loading keystore");
			System.exit(-1);
			return digiSignParamsMap;
		}
		catch (IOException e) 
		{
			System.out.println("Unexpected IOException while loading keystore.");
			System.exit(-1);
			return digiSignParamsMap;
		}
		catch (Exception e) 
		{
			System.out.println("Exception in LunaHsmCertificate / getLunaSignDetails()... " + e.getMessage());
			System.exit(-1);
			return digiSignParamsMap;
		}
			
		//PdfDigiSign.sign(src, dest, certChain, privateKey, DigestAlgorithms.SHA256, provider.getName(), CryptoStandard.CMS, "RBS", "INDIA");
	}

	 public static void intitalizeConst()
     {
        getprops();

		hsmLunaPwd = readini("HSMLUNAPWD");
		hsmLunaSlot = readini("HSMLUNASLOT");
		hsmPkAlias = readini("HSMPRIVATEKEYALIAS");
		hsmLunaLabel = readini("HSMLUNALABEL");
		hsmProvider = readini("HSMKEYSTORE");

		
		System.out.println(" HSM Password  : " + hsmLunaPwd);
		System.out.println(" HSM Luna Slot : " + hsmLunaSlot);
		System.out.println(" Private Alias : " + hsmPkAlias);
		System.out.println(" HSM Label	   : " + hsmLunaLabel);
		System.out.println(" HSM Provider  : " + hsmProvider);
		

		/*try
        {
            StringBuffer stringbuffer = new StringBuffer();
            String s = null;
            String s1 = readini("COVER_LETTER_PATH");
            System.out.println("COVER_LETTER_PATH" + s1);
            FileInputStream fileinputstream = new FileInputStream(s1);
            BufferedReader bufferedreader = new BufferedReader(new InputStreamReader(fileinputstream));
            while((s = bufferedreader.readLine()) != null) 
                stringbuffer.append(s);
            emlmsg = stringbuffer.toString();

			//System.out.println(" Eml Message : " + emlmsg);
        }
        catch(Exception exception1)
        {
            exception1.printStackTrace();
        }*/
		
	 }


	 public static void getprops()
    {
        properties = new Properties();
        Object obj = null;
        Object obj1 = null;
        Runtime runtime = Runtime.getRuntime();
        Object obj2 = null;
        String s = null;
        try
        {
            Process process = runtime.exec("cmd.exe /c set");
            BufferedReader bufferedreader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            do
            {
                String s1;
                if((s1 = bufferedreader.readLine()) == null)
                    break;
                int i = s1.indexOf('=');
                String s2 = s1.substring(0, i);
                String s3 = s1.substring(i + 1);
                if(s2.equals("CORVETTE_HOME"))
                    s = s3;
            } while(true);
        }
        catch(Exception exception)
        {
            System.out.println("Excpetion------>" + exception.toString());
        }
        try
        {
            properties.load(new FileInputStream(s + "\\conf\\abnconfig.ini"));
        }
        catch(Exception exception1)
        {
            System.out.println("configuration file not found: " + exception1.toString());
        }
    }

	private static String readini(String string)
    {
        try
        {
            string = properties.getProperty(string);
        }
        catch(Exception exception)
        {
            System.out.println("configuration file not found: " + exception.toString());
        }
        return string;
    }

	public static void main(String[] args)
	{
		//LunaHsmCertificate.intitalizeConst();
		LunaHsmCertificate.getLunaSignDetails();
	}
}
