package clientServer;
import java.math.BigInteger;
import java.net.Socket;

public class Voter {

	static BigInteger[] publicKeyCLA = { new BigInteger("3"), new BigInteger("28651327031137471") }; // 3,
																										// 28651327031137471
	static BigInteger[] publicKeyCTF = { new BigInteger("3"), new BigInteger("773978785583629") };; // 3,
																									// 773978785583629
	static BigInteger[] myPublicKey = new BigInteger[2];
	static BigInteger[] myPrivateKey = new BigInteger[2];

	private static BigInteger voterId;

	private static String vote;

	private static BigInteger receivedValidNum;

	public static void generateMyKeys() {
		BigInteger[] keys = RSA.generateKeys(new BigInteger("573259433"), new BigInteger("15485867"));
		myPublicKey[0] = keys[0]; // e
		myPrivateKey[0] = keys[1]; // d
		myPublicKey[1] = myPrivateKey[1] = keys[2]; // n
	}

	// network socket
	private Socket s;

	public Voter(String host, int port) throws Exception {
		// open a connection to the server
		s = new Socket(host, port);
		generateMyKeys();
	}

	// data transfer
	public void execute() throws Exception {
		int c;

		if (vote.equals("")) { //this case runs when connecting to CLA to get Validation number.
			BigInteger t = voterId;
			BigInteger encrypted = (t).modPow(publicKeyCLA[0], publicKeyCLA[1]);
			String encryptedIdToSend = encrypted.toString();
			for (int l = 0; l < encryptedIdToSend.length(); l++) {
				s.getOutputStream().write(encryptedIdToSend.charAt(l));
			}
			s.getOutputStream().flush();
			StringBuilder sb2 = new StringBuilder();
			while ((c = s.getInputStream().read()) != -1) {
				sb2.append((char) c);
			}

			BigInteger myValidNum = new BigInteger(sb2.toString());
			BigInteger decryptedValidNum = (myValidNum).modPow(myPrivateKey[0], myPrivateKey[1]);
			System.out.println("Received Validation Number:"+decryptedValidNum);
			receivedValidNum = decryptedValidNum;
		} else { // this case runs when voter is casting vote to CTF after obtaining validation number from CLA
			BigInteger t = receivedValidNum;
			BigInteger encryptedValidNum = (t).modPow(publicKeyCTF[0], publicKeyCTF[1]);
			String encryptedIdToSend = encryptedValidNum.toString();
			for (int l = 0; l < encryptedIdToSend.length(); l++) {
				s.getOutputStream().write(encryptedIdToSend.charAt(l));
			}
			s.getOutputStream().write(32); //separator

			if (s.getInputStream().read() == 0) {
				byte[] m = vote.getBytes();

				for (int l = 0; l < m.length; l++) {
					s.getOutputStream().write(m[l]);
				}
				System.out.println("Your vote has been registered successfully!");
			} else if (s.getInputStream().read() == -1) {
				System.out.println("Unauthorized voter"); //wrong validation number
			} else {
				System.out.println("You have voted already"); // trying to vote again
			}
			s.getOutputStream().flush();
		}
		System.out.println();
		s.close();
	}

	public static void main(String[] argv) throws Exception {
		String host = argv[0];
		int port = Integer.parseInt(argv[1]);
		voterId = new BigInteger(argv[2]);
		receivedValidNum = voterId;
		vote = argv[3];
		new Voter(host, port).execute();
	}
}
