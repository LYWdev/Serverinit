public class Sample {
	public static int end(int value) {
		if (value > 0) {
			System.out.println(value);
			return end(value-1);
		}
		System.out.println("End");
		return value;
	}

	public static int start(int value) {
		while(true) {
			System.out.println("Start");
			end(value);
			try {
				Thread.sleep(1000);
			} catch (InterruptedException e) {
				System.err.format("%s\n", e);
			}
		}
	}

	public static void main(String []args) {
		System.out.println("Hello, world\n");
		start(3);
	}
}
