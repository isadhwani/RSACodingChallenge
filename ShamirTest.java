package ShamirSharing;

import org.junit.Test;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

import static org.junit.Assert.*;

/**
 * A test class for the ShamirProgram.
 */
public class ShamirTest {

  @Test
  public void testGenerateKeyPairs() {
    ShamirProgram.Shamir sham = new ShamirProgram.Shamir("test", 5, 2);
    sham.generateShamirShares();

    String pub = readFromFile("Public.TXT");


      for (int i = 0; i < 5; i++) {
        //System.out.print("Private key written to file: ");
        String currPrivKey = readFromFile("Shard[" + i + "].TXT");
        assertEquals(currPrivKey, (sham.getKey(i) + " "));
      }
    }


  @Test
  public void testEncode() {
    ShamirProgram.Shamir sham = new ShamirProgram.Shamir("helloThere", 3, 2);
    sham.generateShamirShares();
    String pubKey = readFromFile("Public.TXT");
    //assertEquals(pubKey, "Sun RSA public key, 2048 bits  params: null  modulus: 24136608442552902183585933215016507918190858795825825250865548299733181696932120785164573361528986734759706193410934890608191436452189318554652341601029561572212339830295362593147994096345917172232300749071816378214530767161369030371633622032809353269634020221933820070688322214436028145937259507999287217209073079417873714582256894398369813977269697553683849623807119518889127198329697621089940391961197763309865955992817088140108707679370741241874088825810749977059123294378148525008341319487355169097801079987749010041980036742014366727063605342582952604613140966561797957738463789231896278193092931719610707985483  public exponent: 65537");


    for(int i = 1; i < 3; i++) {
      //System.out.print("Private key written to file: ");
      String currPrivKey = readFromFile("Shard[" + i + "].TXT" );
      assertEquals(currPrivKey, (sham.getKey(i)) + " ");
    }
  }

  @Test
  public void testDecode() throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, UnsupportedEncodingException {
    ShamirProgram.Shamir sham = new ShamirProgram.Shamir("test", 5, 2);
    sham.generateShamirShares();

    String shard1Str = readFromFile("Shard[1].TXT");
    ShamirProgram.Shard shard1 = new ShamirProgram.Shard(shard1Str);

    String shard2Str = readFromFile("Shard[2].TXT");
    ShamirProgram.Shard shard2 = new ShamirProgram.Shard(shard2Str);
    assertEquals(shard1.calcPrivateKey(shard2), sham.priv);

     assertEquals("test", sham.decode(shard1.calcPrivateKey(shard2)));
  }

  @Test
  public void testDecode2() throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, UnsupportedEncodingException {
    ShamirProgram.Shamir sham = new ShamirProgram.Shamir("helloFromTheBigIslandOfHawaii", 5, 2);
    sham.generateShamirShares();

    String shard1Str = readFromFile("Shard[1].TXT");
    ShamirProgram.Shard shard1 = new ShamirProgram.Shard(shard1Str);

    String shard2Str = readFromFile("Shard[2].TXT");
    ShamirProgram.Shard shard2 = new ShamirProgram.Shard(shard2Str);

    assertEquals("helloFromTheBigIslandOfHawaii",
            sham.decode(shard1.calcPrivateKey(shard2)));
  }


  /**
   * Reads everything from a given file.
   * @param fileName String representation of the filename
   * @return String everything in the file
   */
  private String readFromFile(String fileName) {
    String ret = "";
    try {
      File file = new File(fileName);
      Scanner sc = new Scanner(file);

      while (sc.hasNextLine()) {
        ret = ret + sc.nextLine();
      }
    } catch (IOException ex) {
      ex.printStackTrace();
    }
    return ret;
  }

}