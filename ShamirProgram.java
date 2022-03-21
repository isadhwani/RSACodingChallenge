package ShamirSharing;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Random;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * A class for controlling the ShamirSecretSharing program.
 */
public class ShamirProgram {
  public ShamirProgram() {
  }

  /**
   * Controller for the ShamirProgram. Takes input and preforms desired tasks.
   *
   * @param args command line arguments
   */
  public static void main(final String[] args) {
    if (args == null) {
      throw new IllegalArgumentException("Missing arguments");
    }


    ShamirController ctrl = new ShamirController(args);
    ctrl.start();
  }

  /**
   * A class for controlling a ShamirProgram
   */
  static class ShamirController {
    private final String[] args;
    static Scanner scan = new Scanner(System.in);
    private String mode;

    ShamirController(String[] args) {
      this.args = args;
    }

    /**
     * Waits for the user to input a valid pile.
     *
     * @return String pile key determined valid
     */
    private String inputMode() {
      String input = null;
      while (input == null) {
        try {
          input = scan.next();
        } catch (NoSuchElementException nse) {
          throw new IllegalStateException("Ran out of readable input");
        }

        if (!input.equals("decode") && !input.equals("encode") && !input.equals("q") &&
                !input.equals("quit")) {
          System.out.println("Invalid input: " + input + "\n");
          input = null;
        }
      }
      return input;
    }

    /**
     * Starts the controller.
     */
    public void start() {
      Shamir sham = null;

      try {
        sham = new Shamir();
      } catch (NoSuchPaddingException | NoSuchAlgorithmException e) {
        throw new IllegalArgumentException("Cannot start program");
      }

      boolean quit = false;
      while (!quit) {

        System.out.println("\nEnter a function for the SecretSharingProgram\n");
        mode = inputMode();

        System.out.println("Valid mode: " + mode + "\n");

        switch (mode.toLowerCase()) {
          case "encode":


            try {
              System.out.println("Enter a word to encode");
              String word = takeStringInput();

              System.out.println("Enter a a number of private key shards to make");
              int numShards = takeIntInput();
              System.out.println("Encoding word: " + word + " and creating " + numShards + " shards");
              // In this case, the threshold will always be 2 because the description specifies
              // that any 2 shards should be able to generate the private key.
              sham = new Shamir(word, numShards, 2);
              sham.generateShamirShares();
            } catch (NumberFormatException e) {
              throw new IllegalArgumentException("Number of shards must be an integer");
            }
            break;


          case "decode":

            System.out.println("Enter the first input");
            int input1 = takeIntInput();

            System.out.println("Enter the first shard value");
            BigInteger value1 = takeBigIntInput();

            System.out.println("Enter the second input");
            int input2 = takeIntInput();

            System.out.println("Enter the second shard value");
            BigInteger value2 = takeBigIntInput();

            try {
              Shard shard1 = new Shard(input1, value1);
              Shard shard2 = new Shard(input2, value2);

              PrivateKey privateKey = shard1.calcPrivateKey(shard2);
              System.out.println("Reassembled Private Key: " + privateKey + "\n\n");

              System.out.println("Decoded word: " + sham.decode(privateKey));


            } catch (NoSuchAlgorithmException | InvalidKeySpecException | NumberFormatException e) {
              throw new IllegalArgumentException("Could not generate private key");
            }
            break;
          case "quit":
          case "q":
            System.out.println("Quitting the program");
            quit = true;
            break;

          default:
            System.out.println("Invalid arguments");
        }
      }
    }

    /**
     * Takes a BigInteger input.
     * @return BigInteger inputed
     */
    private static BigInteger takeBigIntInput() {
      String input = takeStringInput();
      BigInteger ret = null;

      while (ret == null) {
        try {
          ret = new BigInteger(input);

        } catch (NumberFormatException e) {
          System.out.println("Invalid input");
        }
      }
      return ret;
    }

    /**
     * Loops until a valid Integer is input.
     *
     * @return int input int
     */
    private static int takeIntInput() {
      Integer input = null;
      while (input == null) {
        String value = scan.next();
        try {
          input = Integer.parseInt(value);

        } catch (NumberFormatException nfe) {
          System.out.println("Invalid integer: " + "\n");
        }
      }
      return input.intValue();
    }

    /**
     * Waits until a valid String is input by the user.
     * @return String inputed String
     */
    private static String takeStringInput() {
      String input = null;
      while (input == null) {
        try {
          input = scan.next();
        } catch (NoSuchElementException nse) {
          throw new IllegalStateException("Ran out of readable input");
        }
      }
      return input;
    }

  }


  /**
   * A class for encrypting and decrypting strings using Shamir's Secret Sharing Algorithm.
   */
  static class Shamir {
    private final byte[] cipherText;
    private final Key pub;
    final PrivateKey priv;
    private final Cipher cipher;

    private List<Shard> shards;
    private int threshold;
    private int numShards;
    private BigInteger encodedPrivKey;

    public Shamir(String secret, int numShards, int threshold) {
      if (threshold > numShards) {
        throw new IllegalArgumentException("Threshold cannot be larger then number of shares");
      }

      this.numShards = numShards;
      this.threshold = threshold;

      // Generate public and private keys
      try {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        pub = kp.getPublic();
        priv = kp.getPrivate();
        encodedPrivKey = new BigInteger(priv.getEncoded());

        this.cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

        //Create cipher
        cipher.init(Cipher.ENCRYPT_MODE, pub);

        // Turns the secret into a byte array and encrypts it into cipherText
        byte[] plainText  = secret.getBytes("UTF-8");
        cipherText = cipher.doFinal(plainText);

        // Writes public key to file
        writeToFile("Public.TXT", pub.toString());

      } catch (NoSuchAlgorithmException | IOException | InvalidKeyException
              | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e) {
        throw new IllegalArgumentException("Cannot create keys");
      }
    }


    public Shamir() throws NoSuchPaddingException, NoSuchAlgorithmException {
      this("", 5, 2);
    }

    /**
     * Writes data to a given file.
     *
     * @param outFile String name of the file
     * @param data    byte[] data to be written to file
     * @throws IOException if it cannot find the file
     */
    void writeToFile(String outFile, String data) throws IOException {
      BufferedWriter writer = new BufferedWriter(
              new FileWriter(outFile));
      writer.write(data + " ");
      writer.close();
    }

    /**
     * Divides a given secret into a number of shards.
     *
     * @param random Random object to make coefficent
     * @return List<BigInteger> list representing the private keys
     */
    public List<Shard> split(Random random) {

      // first, generate a random coefficient between 0-100
      int slope = random.nextInt(50);

      List<Shard> ret = new ArrayList<>(numShards);
      // FORMULA: shard value = secret + coeff * input
      // coeff == slope
      // any 2 private keys should form the original private key!
      // Sub in values for x and that, with the index is the sharded key

      for (int i = 0; i < numShards; i++) {

        // Generate random input
        int input = random.nextInt(50);

        // Creates a BigInteger value by adding the original secret to the current index *
        // the random coefficient
        BigInteger shardValue = encodedPrivKey.add(new BigInteger("" + (slope * input)));
        Shard currShard = (new Shard(input, shardValue));
        ret.add(currShard);

        // Writes each private key to its corresponding text file
        try {
          //System.out.println("Writing private key: " + currShard);
          String fileName = "Shard[" + i + "].TXT";
          writeToFile(fileName, currShard.toString());

        } catch (IOException e) {
          throw new IllegalArgumentException("Cannot access file");
        }

      }

      return ret;
    }


    /**
     * Using the fields of this class, generates shards based on numShards always using a threshold
     * of two.
     */
    public void generateShamirShares() {
      // Create a BigInteger representation from secret.getBytes();
      final SecureRandom random = new SecureRandom();

      // Generates an array of shards
      shards = split(random);
    }

    /**
     * Returns a String representation of a Shard stored at a given index.
     *
     * @param i index of desired Shard
     * @return String representation of the shard
     * @throws IllegalArgumentException if the given index does not exisit
     */
    public String getKey(int i) {
      if (shards.size() >= i) {
        return shards.get(i).toString();
      }
      throw new IllegalArgumentException("Invalid index");
    }

    /**
     * Decodes the Cipher with a given PrivateKey and the saved cipherText
     * @param privateKey PrivateKey used for decoding
     * @return String decoded secret
     */
    public String decode(PrivateKey privateKey) {

      try {
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] plainText = cipher.doFinal(cipherText);
        return new String(plainText);

        //return new String(cipher.doFinal(cipherText)); // ———Add this line——–
      } catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException e) {
        throw new IllegalArgumentException(e.getMessage());
      }

    }
  }

  /**
   * A class that represents a Shard of a private key.
   */
  static class Shard {
    private final int input;
    private final BigInteger value;


    /**
     * Public constructor for a Shard.
     *
     * @param input int input
     * @param value BigInteger share
     */
    public Shard(int input, BigInteger value) {
      if (value == null) {
        throw new IllegalArgumentException("Value cannot be null");
      }
      this.input = input;
      this.value = value;
    }

    /**
     * Constructor for creating a Shard with a String. Used for decoding and reading from a file.
     *
     * @param sh String representation of a Shard
     * @throws IllegalArgumentException if the given String is invalid
     */
    public Shard(String sh) {
      String[] temp = sh.split(" ");
      try {
        this.input = Integer.parseInt(temp[0]);
        this.value = new BigInteger(temp[1]);
      } catch (NumberFormatException e) {
        throw new IllegalArgumentException("Invalid Shard");
      }
    }


    /**
     * Gets the input of this share.
     *
     * @return int input
     */
    public int getInput() {
      return input;
    }

    /**
     * Gets a copy of this shards value
     *
     * @return
     */
    public BigInteger getValue() {
      return value;
    }


    public String toString() {
      return input + " " + value;
    }

    /**
     * Determines the original private key from 2 Shards
     *
     * @param other
     * @return BigInteger
     */
    public PrivateKey calcPrivateKey(Shard other) throws NoSuchAlgorithmException, InvalidKeySpecException {
      BigInteger top = this.value.subtract(other.value);
      BigInteger bot = new BigInteger("" + (this.input - other.input));

      // Calculates slope
      BigInteger slope = top.divide(bot);

      // Wrap the int input as a BigInteger so it can be used in equation
      BigInteger input = new BigInteger("" + (this.input));

      // Calculate y intercept by subtracting the value from (input * slope)
      // y = mx + b
      // value = slope * input + intercept
      // intercept = value - (slope * input)
      // return intercept.toByteArray()
      // intercept == privateKey!
      BigInteger intercept = this.value.subtract(input.multiply(slope));
      PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(intercept.toByteArray());
      KeyFactory factory = KeyFactory.getInstance("RSA");
      return factory.generatePrivate(keySpec);
    }
  }
}
