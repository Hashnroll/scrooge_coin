import java.util.ArrayList;


public class TxHandler {

	UTXOPool pool;
	
    /**
     * Creates a public ledger whose current UTXOPool (collection of unspent transaction outputs) is
     * {@code utxoPool}. This should make a copy of utxoPool by using the UTXOPool(UTXOPool uPool)
     * constructor.
     */
	
    public TxHandler(UTXOPool utxoPool) {
        // IMPLEMENT THIS
    	
    	 pool = new UTXOPool(utxoPool);
    	
    }

    /**
     * @return true if:
     * (1) all outputs claimed by {@code tx} are in the current UTXO pool, 
     * (2) the signatures on each input of {@code tx} are valid, 
     * (3) no UTXO is claimed multiple times by {@code tx},
     * (4) all of {@code tx}s output values are non-negative, and
     * (5) the sum of {@code tx}s input values is greater than or equal to the sum of its output
     *     values; and false otherwise.
     */
    public boolean isValidTx(Transaction tx) {
        // IMPLEMENT THIS
    	
    	UTXOPool sandboxPool = new UTXOPool(pool); /*sandboxPool is needed cause maybe this Tx won't be included so the real pool stays valid*/
    	
    	Double inputSum = 0.0, outputSum = 0.0;
    	
    	ArrayList<Transaction.Input> prevoutputs = tx.getInputs();
    	for (int i = 0; i<prevoutputs.size(); ++i){
    		Transaction.Input prevop = prevoutputs.get(i);
    		UTXO ut = new UTXO(prevop.prevTxHash, prevop.outputIndex);
    	
    		if (!sandboxPool.contains(ut)) {
    				return false;
    		}
    		else {
    			Transaction.Output op = sandboxPool.getTxOutput(ut);
    			java.security.PublicKey pk = op.address;
    			byte[] sig = prevop.signature;
    			byte[] msg = tx.getRawDataToSign(i);
    			
    			if (!Crypto.verifySignature(pk, msg, sig))
    				return false;
    			
    			sandboxPool.removeUTXO(ut);
    			inputSum += op.value;
    		}
    	}
    			
    	ArrayList<Transaction.Output> ops = tx.getOutputs();
    				
    	for (Transaction.Output op : ops) {
    		if (op.value < 0)
    			return false;
    		
    		outputSum += op.value;
    	}
    			
    	if (outputSum > inputSum)
    		return false;
    	
    	return true;
    }

    /**
     * Handles each epoch by receiving an unordered array of proposed transactions, checking each
     * transaction for correctness, returning a mutually valid array of accepted transactions, and
     * updating the current UTXO pool as appropriate.
     */
    public Transaction[] handleTxs(Transaction[] possibleTxs) {
        // IMPLEMENT THIS
    	ArrayList<Transaction> result = new ArrayList<Transaction>();
    	for (Transaction tx : possibleTxs) {
    		if (isValidTx(tx)) {
    			result.add(tx);
    			
    			//removing used inputs to prevent double-spend
    			ArrayList<Transaction.Input> prevoutputs = tx.getInputs();
    			for (int i = 0; i<prevoutputs.size(); ++i){
    	    		Transaction.Input prevop = prevoutputs.get(i);
    	    		UTXO ut = new UTXO(prevop.prevTxHash, prevop.outputIndex);
    	    		pool.removeUTXO(ut);
    			}
    		}
    	}  
    	Transaction[] a = result.toArray(new Transaction[result.size()]);
    	return a;
    }

}
