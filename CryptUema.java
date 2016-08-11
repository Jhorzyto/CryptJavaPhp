import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class CryptUema {

    static char[] HEX_CHARS = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};

    private String ivParams     = "9876543210fedcba";
    private String chaveSecreta = "sigUema.12qwaszx";
    private IvParameterSpec ivParamsSpec;
    private SecretKeySpec keySpec;
    private Cipher cipher;
    private static boolean fail;
    private static String message;
    private static CryptUema instance;

    private CryptUema() {
        try {
            this.ivParamsSpec = new IvParameterSpec(this.ivParams.getBytes());
            this.keySpec      = new SecretKeySpec(this.chaveSecreta.getBytes(), "AES");
            this.cipher       = Cipher.getInstance("AES/CBC/NoPadding");
        } catch (GeneralSecurityException e) {
            CryptUema.fail    = true;
            CryptUema.message = e.getMessage();
        }
    }

    private static CryptUema getInstance() throws Exception{
        if(CryptUema.instance == null)
            CryptUema.instance = new CryptUema();

        if(CryptUema.fail)
            throw new Exception(CryptUema.message);

        return CryptUema.instance;
    }

    public static String encrypt(Long numero){
        return CryptUema.encrypt(numero.toString());
    }

    public static String encrypt(long numero){
        return CryptUema.encrypt(Long.toString(numero));
    }

    public static String encrypt(Integer numero){
        return CryptUema.encrypt(numero.toString());
    }

    public static String encrypt(int numero){
        return CryptUema.encrypt(Long.toString(numero));
    }

    public static String encrypt(String texto){
        try {
            return CryptUema.bytesToHex(CryptUema.getInstance().encryptInternal(texto));
        } catch (Exception e){
            CryptUema.fail    = true;
            CryptUema.message = e.getMessage();
            return null;
        }
    }

    public static String decrypt(String codigo){
        try {
            return new String(CryptUema.getInstance().decryptInternal(codigo));
        } catch (Exception e){
            CryptUema.fail    = true;
            CryptUema.message = e.getMessage();
            return null;
        }
    }

    public static String getMessage(){
        return CryptUema.message;
    }

    public static boolean isFail(){
        return CryptUema.fail;
    }

    private byte[] encryptInternal(String texto) throws Exception {
        if(texto == null || texto.length() == 0)
            throw new Exception("Texto vazio!");

        byte[] encrypted = null;

        try {
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivParamsSpec);
            encrypted = cipher.doFinal(padString(texto).getBytes());
            return encrypted;
        } catch (Exception e){
            throw new Exception("[encrypt] " + e.getMessage());
        }
    }

    private byte[] decryptInternal(String codigo) throws Exception {
        if(codigo == null || codigo.length() == 0)
            throw new Exception("Texto vazio!");

        byte[] decrypted = null;

        try {
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivParamsSpec);
            decrypted = cipher.doFinal(hexToBytes(codigo));

            if (decrypted.length > 0) {
                int trim = 0;
                for (int i = decrypted.length - 1; i >= 0; i--) if (decrypted[i] == 0) trim++;

                if (trim > 0) {
                    byte[] newArray = new byte[decrypted.length - trim];
                    System.arraycopy(decrypted, 0, newArray, 0, decrypted.length - trim);
                    decrypted = newArray;
                }
            }
            return decrypted;
        } catch (Exception e) {
            throw new Exception("[decrypt] " + e.getMessage());
        }
    }

    private static String bytesToHex(byte[] buf) {
        char[] chars = new char[2 * buf.length];
        for (int i = 0; i < buf.length; ++i) {
            chars[2 * i] = HEX_CHARS[(buf[i] & 0xF0) >>> 4];
            chars[2 * i + 1] = HEX_CHARS[buf[i] & 0x0F];
        }
        return new String(chars);
    }

    private static byte[] hexToBytes(String str) {
        if (str == null) {
            return null;
        } else if (str.length() < 2) {
            return null;
        } else {
            int len = str.length() / 2;
            byte[] buffer = new byte[len];
            for (int i = 0; i < len; i++) {
                buffer[i] = (byte) Integer.parseInt(str.substring(i * 2, i * 2 + 2), 16);
            }
            return buffer;
        }
    }

    private static String padString(String source) {
        char paddingChar = 0;
        int size = 16;
        int x = source.length() % size;
        int padLength = size - x;

        for (int i = 0; i < padLength; i++) {
            source += paddingChar;
        }

        return source;
    }
}