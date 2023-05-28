package ClientServer;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;

public class Server {
	
	
	public static void main(String[] args) throws IOException
	{
		ServerSocket serverSocket;
	    Socket clientSocket;
	    PrintWriter out;
	    BufferedReader in;
	    serverSocket = new ServerSocket(194);
	    clientSocket = serverSocket.accept();
	    out = new PrintWriter(clientSocket.getOutputStream(), true);
	    in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
	    String greeting = in.readLine();
	    System.out.println("Client: " + greeting);
	}
	
}

