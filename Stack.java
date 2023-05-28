
public class Stack<T> {
	
	Node<T> Top;
	
	public Stack()
	{
		this.Top = null;
	}
	
	public boolean isEmpty()
	{
		return Top == null;
	}
	
	public void Push(T Value)
	{
		Node node = new Node();
		node.Value = Value;
		node.Link = Top;
		Top = node;

	}
	
	public T Peek()
	{
		if(!isEmpty())
			return Top.Value;
		else
			return null;
	}
	
	public void Pop()
	{
		if(Top == null)
		{
			System.err.println("Stackoverflow");
			return;
		}
		
		Top = Top.Link;
	}
	
	public void PrintStack()
	{
		if(Top != null)
		{
			Node temp = Top;
			
			while(temp != null)
			{
				System.out.print(temp.Value + " ");
				temp = temp.Link;
			}
		}		
	}
	
	
	 public static void main(String[] args)
	    {

	        Stack stack = new Stack();
	        
	        stack.Push(Math.sqrt(81));
	        stack.Push(Math.sqrt(64));
	        stack.Push(Math.sqrt(49));
	        stack.Push(Math.sqrt(36));
	 
	        stack.PrintStack();
	    }
}
