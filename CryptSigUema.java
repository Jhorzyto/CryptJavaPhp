import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;

public class CryptSigUema {

    static char[] HEX_CHARS = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};

    private String ivParams     = "9876543210fedcba";
    private String chaveSecreta = "sigUema.12qwaszx";
    private IvParameterSpec ivParamsSpec;
    private SecretKeySpec keySpec;
    private Cipher cipher;
    private static boolean fail;
    private static String message;
    private static CryptSigUema instance;

    private CryptSigUema() {
        try {
            this.ivParamsSpec = new IvParameterSpec(this.ivParams.getBytes());
            this.keySpec      = new SecretKeySpec(this.chaveSecreta.getBytes(), "AES");
            this.cipher       = Cipher.getInstance("AES/CBC/NoPadding");
        } catch (GeneralSecurityException e) {
            CryptSigUema.fail    = true;
            CryptSigUema.message = e.getMessage();
        }
    }

    private static CryptSigUema getInstance() throws Exception{
        if(CryptSigUema.instance == null)
            CryptSigUema.instance = new CryptSigUema();

        if(CryptSigUema.fail)
            throw new Exception(CryptSigUema.message);

        return CryptSigUema.instance;
    }

    public static String encrypt(Long numero){
        return CryptSigUema.encrypt(numero.toString());
    }

    public static String encrypt(long numero){
        return CryptSigUema.encrypt(Long.toString(numero));
    }

    public static String encrypt(Integer numero){
        return CryptSigUema.encrypt(numero.toString());
    }

    public static String encrypt(int numero){
        return CryptSigUema.encrypt(Long.toString(numero));
    }

    public static String encrypt(String texto){
        try {
            return CryptSigUema.bytesToHex(CryptSigUema.getInstance().encryptInternal(texto));
        } catch (Exception e){
            CryptSigUema.fail    = true;
            CryptSigUema.message = e.getMessage();
            return null;
        }
    }

    public static String getMessage(){
        return CryptSigUema.message;
    }

    public static boolean isFail(){
        return CryptSigUema.fail;
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

    private static String bytesToHex(byte[] buf) {
        char[] chars = new char[2 * buf.length];
        for (int i = 0; i < buf.length; ++i) {
            chars[2 * i] = HEX_CHARS[(buf[i] & 0xF0) >>> 4];
            chars[2 * i + 1] = HEX_CHARS[buf[i] & 0x0F];
        }
        return new String(chars);
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
