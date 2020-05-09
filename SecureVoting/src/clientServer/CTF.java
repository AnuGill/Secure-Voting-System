package clientServer;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class CTF {

	static BigInteger[] publicKeyVoter = { new BigInteger("5"), new BigInteger("8877419335933411") }; // 5,
																										// 8877419335933411
	static BigInteger[] publicKeyCLA = { new BigInteger("3"), new BigInteger("28651327031137471") }; // 3,
																										// 28651327031137471
	static BigInteger[] myPublicKey = new BigInteger[2];
	static BigInteger[] myPrivateKey = new BigInteger[2];
	static Map<String, Integer> tally = new HashMap<>();
	static Set<Integer> validationNums = new HashSet<>();
	static Set<Integer> oldValidationNums = new HashSet<>();
	boolean isValid = true;

	private ServerSocket s;

	public CTF(int p) throws Exception {
		// open server socket and start listening
		s = new ServerSocket(p);
		generateMyKeys();
	}

	public void generateMyKeys() {
		BigInteger[] keys = RSA.generateKeys(new BigInteger("49979687"), new BigInteger("15485867"));
		myPublicKey[0] = keys[0]; // e
		myPrivateKey[0] = keys[1]; // d
		myPublicKey[1] = myPrivateKey[1] = keys[2]; // n
	}

	public class RequestHandler implements Runnable {
		private Socket sock;

		private RequestHandler(java.net.Socket x) {
			sock = x;
		}

		public void run() {
			try {
				System.out.println("connect...");
				int c;

				StringBuilder sb = new StringBuilder();

				while ((c = sock.getInputStream().read()) != -1) {
					if (c == 32) {
						isValid = false;
						break;
					}
					sb.append(c - '0');
				}

				BigInteger validNum = new BigInteger(sb.toString());
				BigInteger decryptedValidNum = (validNum).modPow(myPrivateKey[0], myPrivateKey[1]);
				System.out.println("Received Validation Number:"+decryptedValidNum);
				if (isValid)
					validationNums.add(decryptedValidNum.intValue());

				if (!isValid) {
					if (validationNums.contains(decryptedValidNum.intValue())) {
						sock.getOutputStream().write(0);
						StringBuilder sb2 = new StringBuilder();
						while ((c = sock.getInputStream().read()) != -1) {
							sb2.append((char) c);
						}
						String receivedVote = sb2.toString();
						tally.put(receivedVote, tally.getOrDefault(receivedVote, 0) + 1); //adds the successful vote to the tally
						printResult();
						oldValidationNums.add(decryptedValidNum.intValue()); //keeps record of used validation numbers.
						validationNums.remove(decryptedValidNum.intValue()); // deletes this validation number
					} else {
						if (oldValidationNums.contains(decryptedValidNum.intValue())) {
							sock.getOutputStream().write(-2); //if this voter has already voted.
							sock.getOutputStream().write(1);
						}
					}
					isValid = true;
				} else
					return;
				sock.getOutputStream().flush();
				sock.close();
				System.out.println("disconnect...");
			} catch (Exception e) {
				System.out.println("HANDLER: " + e);
			}
		}
	}
   
	public static void printResult() {
		if (tally.isEmpty())
			System.out.println("No votes have been registered yet!");
		for (Map.Entry<String, Integer> entry : tally.entrySet()){
			System.out.println("Candidate = " + entry.getKey() + ", Vote Count = " + entry.getValue());
		}
	}

	public void run() {
		while (true) {
			try {
				// accept a connection and run handler in a new thread
				new Thread(new RequestHandler(s.accept())).run();
			} catch (Exception e) {
				System.out.println("SERVER: " + e);
			}
		}
	}

	public static void main(String[] argv) throws Exception {
		if (argv.length != 1) {
			System.out.println("java SimpleServer <port>");
			System.exit(1);
		}
		new CTF(Integer.parseInt(argv[0])).run();
	}

}
