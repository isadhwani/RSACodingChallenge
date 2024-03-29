README.md

You can run this tool it by running the provided bash script that encodes the word test, opening the java program and running my junit tests, or running it from the command line. To encode a word, enter the word "encode" followed by the word you want to encode and the number of desired shards. To decode a word, enter the word "decode" followed by 4 numbers. Two numbers make up a shard, and two shards are required for decoding. The shards are very large number, so you will need to use the command stty -icanon to extend max inputs. 

The way I designed this program was first by using Java's built in libraries for creating a public and private key. Then,  I would turn the given word into a BigInteger by calling getBytes on the input String. Then, to generate shards I first created a random integer from 0-100 to be the slope. I designed a loop that created the desired number of shards and generated an input for each shard. Then, I designed a formula with that BigInteger being the y intercept. The shard value was determined by adding the intercept to (input * slope). If the program were to support thresholds greater then 2(specified in project description that any two keys should be able to decode), then I would have to generate a formula of degree threshold - 1. The program would then write each shard input and value to its corresponding text file. 

For decrypting, I designed two methods. One for taking in two Shard objects and one that compiled with two Strings. The string version is what reading from the text file would do first. After parsing input, the String version would call the Shard version. Once the program builds two shards, it would calculate the slope from the two points. This slope will match the random coefficent generated earlier. Then, the intercept would be determined by subtracting one points value from (input * slope). This intercept could then be decoded into the secret word.

Here is a quick example of how the byte array storage fails
    byte[] hawaii = "hawaii".getBytes(StandardCharsets.UTF_8);
    String encoded = Base64.getEncoder().encodeToString(hawaii);
    byte[] newHawaii = Base64.getDecoder().decode(encoded);
    assertEquals(hawaii, newHawaii); // This test will fail

A solution I made was keeping the program running after a word is encoded, so the byte[] array is available after a word is encoded. This made the program tougher to control from the command line, but it is now fully opperationable. The provided bash script provides instructions on how to run the program from the command line and serves as a unit test. In the repo there are three files with more extensibe tests, ShardTest.java, ShamirTest.java and ShamirControllerTest.java. Running any of these will show that the code is well tested well implemented. 
