/**
 * Created by jhordan on 11/08/16.
 */
public class Crypt {

    public static void main(String args[]){
        try{
            System.out.println(CryptUema.encrypt("Jhordan"));
        } catch (Exception e){
            System.out.println(e.getMessage());
        }
    }
}
