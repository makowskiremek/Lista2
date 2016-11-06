package Coder;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.cert.X509Certificate;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.xml.bind.DatatypeConverter;

import org.apache.commons.codec.binary.Base64;

public class Crypto {

    private String aes = "aes";
    private String type;
    private String keyStoreLocation;
    private String keyID;
    private char[] storePass = {'p','a','s','s','w','o','r','d'};
    private char[] keypassword;
    private char[] specialPass;

    Crypto(String type, String keyStoreLocation, String keyID){

        this.type = type;
        this.keyStoreLocation = keyStoreLocation;
        this.keyID = keyID;
    }
    Crypto(String type, String keyStoreLocation, String keyID, char[] pass){
        this.specialPass = pass;
        this.type = type;
        this.keyStoreLocation = keyStoreLocation;
        this.keyID = keyID;
    }

    public static void main(String[] args){

        Crypto c = new Crypto("CBC","keyStore.jks","audioKey");
        Key k = c.init();
        if(k == null){
            return;
        }
        //zaszyfrowanie pliku i odszyfrowanie go
        String file1 = "audio";
        String ext = ".mp3";
        try {



            String file = "audio.mp3.enc";

            c.encrypt("audio.mp3",k);

            c.decrypt(file,k);
            //byte[] res = c.decryptByte(k,Base64.encodeBase64String(Files.readAllBytes(new File(file).toPath())));
           // OutputStream writer = new FileOutputStream("test.mp3");
           // writer.write(res);
           // writer.close();




            //String content = "OK|keyStore.jks|audioKey|pass";

            //OutputStream write = new FileOutputStream("player");
            //write.write(content.getBytes("UTF-8"));
            //write.close();
            //c.encryptString("player","config",k,"");
            //Files.deleteIfExists(new File("player").toPath());

            //Path path2 = Paths.get("player.config");
            //String res = c.decrypt(k,Base64.encodeBase64String(Files.readAllBytes(path2)));
            //System.out.println(res);
            //c.decryptConfg("player","config",k);

            //read bytes from file.ext
            /*Path path = Paths.get(file+ext);
            byte[] data = Files.readAllBytes(path);
            //string with encrypted file.ext (arg1 is Base64String!)
            String enc = c.encrypt(k, Base64.encodeBase64String(data));

            //encrypt file from file.ext (arg1 is Base64String)
            FileOutputStream fos1 = new FileOutputStream(file+".enc");
            fos1.write(c.encryptByte(k, Base64.encodeBase64String(data)));
            fos1.close();

            //decrypt from string returned by Crypto.encrypt();
            FileOutputStream fos2 = new FileOutputStream(file+"_dec"+ext);
            fos2.write(c.decryptByte(k, enc));
            fos2.close();

            //decrypt from file.enc (aes decoded *.mp3 file)
            Path path2 = Paths.get(file+".enc");
            FileOutputStream fos3 = new FileOutputStream(file+"_dec2"+ext);
            fos3.write(c.decryptByte(k, Base64.encodeBase64String(Files.readAllBytes(path2))));
            fos3.close();*/
        } catch (IOException e) {
            e.printStackTrace();
        }


    }

    public Key init(){

        if(specialPass == null) {
            //GET PASSWORD TO KEYSTORE
            JPanel panel = new JPanel();
            JLabel label = new JLabel("Enter a password:");
            JPasswordField pass = new JPasswordField(10);
            panel.add(label);
            panel.add(pass);
            String[] options = new String[]{"OK", "Cancel"};
            int option = JOptionPane.showOptionDialog(null, panel, "Password",
                    JOptionPane.NO_OPTION, JOptionPane.PLAIN_MESSAGE,
                    null, options, options[0]);
            if (option == 0 && pass.getPassword().length > 0) // pressing OK button with non-empty passfield
            {
                keypassword = pass.getPassword();
                //System.out.println("Your password is: " + new String(keypassword));
            }
        } else {
            keypassword = specialPass;
        }

        File f = new File(keyStoreLocation);
        if(f.exists()){
            //istnieje keystore, weź klucz(?)
            try {
                KeyStore ks = KeyStore.getInstance("JCEKS");
                InputStream readStream = new FileInputStream(keyStoreLocation);
                ks.load(readStream, storePass);
                Key key = ks.getKey(keyID, keypassword);
                readStream.close();
                return key;
            } catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException | CertificateException
                    | IOException e) {
                e.printStackTrace();
            }
        } else {
            //utwórz keystore i pare kluczy
            try {
                KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
                keyGen.init(256, random);
                Key key1 = keyGen.generateKey();

                KeyStore ks = KeyStore.getInstance("JCEKS");
                ks.load(null, storePass);
                ks.setKeyEntry(keyID, key1, keypassword, null);
                OutputStream writeStream = new FileOutputStream(keyStoreLocation);
                ks.store(writeStream, storePass);
                writeStream.close();

                InputStream readStream = new FileInputStream(keyStoreLocation);
                ks.load(readStream, storePass);
                Key key2 = ks.getKey(keyID, keypassword);
                readStream.close();
                return key2;

            } catch (NoSuchAlgorithmException | NoSuchProviderException | KeyStoreException | CertificateException | IOException | UnrecoverableKeyException e) {
                e.printStackTrace();
            }
        }
        return null;
    }

    private String decrypt(Key key, String enc) {
        try {
            IvParameterSpec iv;
            Cipher cipher;
            SecretKeySpec skeySpec;
            byte[] ivec = DatatypeConverter.parseHexBinary("c0e37f633d90b3390a8a24872536fca8");
            iv = new IvParameterSpec(ivec);

            cipher = Cipher.getInstance(aes+"/"+type+"/PKCS5PADDING");
            skeySpec = new SecretKeySpec(key.getEncoded(), "AES");
            if(type.equals("CBC")){
                cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
            } else if(type.equals("ECB")){
                cipher.init(Cipher.DECRYPT_MODE, skeySpec);
            } else {
                cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
            }

            //Base64.decodeBase64(enc)
            byte[] original = cipher.doFinal(Base64.decodeBase64(enc));

            return new String(original);
        } catch (Exception ex) {
            //coś poszło nie tak
            ex.printStackTrace();
        }
        return null;
    }
    private byte[] decryptByte(Key key, String enc) {
        try {
            IvParameterSpec iv;
            Cipher cipher;
            SecretKeySpec skeySpec;
            byte[] ivec = DatatypeConverter.parseHexBinary("c0e37f633d90b3390a8a24872536fca8");
            iv = new IvParameterSpec(ivec);

            cipher = Cipher.getInstance(aes+"/"+type+"/PKCS5PADDING");
            skeySpec = new SecretKeySpec(key.getEncoded(), "AES");

            if(type.equals("CBC")){
                cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
            } else if(type.equals("ECB")){
                cipher.init(Cipher.DECRYPT_MODE, skeySpec);
            } else {
                cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
            }
            //Base64.decodeBase64(enc)
            byte[] original = cipher.doFinal(Base64.decodeBase64(enc));

            return original;
        } catch (Exception ex) {
            //coś poszło nie tak
            ex.printStackTrace();
        }
        return null;
    }


    private String encrypt(Key key, String value) {
        try {
            IvParameterSpec iv;
            Cipher cipher;
            SecretKeySpec skeySpec;
            byte[] ivec = DatatypeConverter.parseHexBinary("c0e37f633d90b3390a8a24872536fca8");
            iv = new IvParameterSpec(ivec);

            cipher = Cipher.getInstance(aes+"/"+type+"/PKCS5PADDING");
            skeySpec = new SecretKeySpec(key.getEncoded(), "AES");

            if(type.equals("CBC")){
                cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
            } else if(type.equals("ECB")){
                cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
            } else {
                cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
            }
            //Base64.decodeBase64(enc)
            byte[] original = cipher.doFinal(Base64.decodeBase64(value));

            return Base64.encodeBase64String(original);
        } catch (Exception ex) {
            //coś poszło nie tak
            ex.printStackTrace();
        }
        return null;
    }
    private byte[] encryptByte(Key key, String value) {
        try {
            IvParameterSpec iv;
            Cipher cipher;
            SecretKeySpec skeySpec;
            byte[] ivec = DatatypeConverter.parseHexBinary("c0e37f633d90b3390a8a24872536fca8");
            iv = new IvParameterSpec(ivec);

            cipher = Cipher.getInstance(aes+"/"+type+"/PKCS5PADDING");
            skeySpec = new SecretKeySpec(key.getEncoded(), "AES");

            if(type.equals("CBC")){
                cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
            } else if(type.equals("ECB")){
                cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
            } else {
                cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
            }
            //Base64.decodeBase64(enc)
            byte[] original = cipher.doFinal(Base64.decodeBase64(value));

            return original;
        } catch (Exception ex) {
            //coś poszło nie tak
            ex.printStackTrace();
        }
        return null;
    }

    //encrypt file and save it as filename.enc
    public void encrypt(String filename, Key k) throws IOException{
        //read bytes from file.ext
        Path path = Paths.get(filename);
        byte[] data = Files.readAllBytes(path);

        //encrypt file from file.ext (arg1 is Base64String)
        FileOutputStream fos1 = new FileOutputStream(filename+".enc");
        fos1.write(encryptByte(k, Base64.encodeBase64String(data)));
        fos1.close();
    }

    //encrypt string
    public void encryptString(String filename, String ext, Key k, String text) throws IOException{
        //read bytes from string
        Path path = Paths.get(filename);
        byte[] data = Files.readAllBytes(path);

        //encrypt file from file.ext (arg1 is Base64String)
        FileOutputStream fos1 = new FileOutputStream(filename+".config");
        fos1.write(encryptByte(k, Base64.encodeBase64String(data)));
        fos1.close();
    }

    //decrypt file(assumed 3letters extension (.enc default) and mp3 file data (deletes last 4 characters which are assumed to be ".enc")
    public void decrypt(String filename, Key k) throws IOException{
        Path path2 = Paths.get(filename);
        FileOutputStream fos3 = new FileOutputStream("new_"+filename.substring(0,filename.length()-4));
        fos3.write(decryptByte(k, Base64.encodeBase64String(Files.readAllBytes(path2))));
        fos3.close();
    }

    //
    public String decryptConfg(String filename, String ext, Key k) throws IOException{
        Path path2 = Paths.get(filename+"."+ext);
        String res = decrypt(k, Base64.encodeBase64String(Files.readAllBytes(path2)));
        System.out.println(res);
        return res;
    }

    //decrypt String created from byteArray
    public void decryptString(String filename,Key k, String enc) throws IOException{
        FileOutputStream fos2 = new FileOutputStream(filename.substring(0,filename.length()-4));
        fos2.write(decryptByte(k, enc));
        fos2.close();
    }



}
