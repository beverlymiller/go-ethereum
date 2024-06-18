// core/helpers.go

package core

import (
	"fmt"
	"log"

	"github.com/ethereum/go-ethereum/core/types"
)

func SimulateTxs(txs []*types.Transaction) error {

	for i, tx := range txs {
		fmt.Println("txs index: %d", i)
		SimulateTx(tx)
	}
	return nil
}

// HelperFunction processes the transaction and can be used by both ethapi and txpool
func SimulateTx(tx *types.Transaction) error {
	from, err := types.Sender(types.NewEIP155Signer(tx.ChainId()), tx)
	if err != nil {
		return fmt.Errorf("failed to get sender: %w", err)
	}
	to := tx.To()
	value := tx.Value()
	gasPrice := tx.GasPrice()
	gasLimit := tx.Gas()
	nonce := tx.Nonce()
	data := tx.Data()

	fmt.Println("From:", from.Hex())
	if to != nil {
		fmt.Println("To:", to.Hex())
	} else {
		fmt.Println("To: Contract Creation")
	}
	fmt.Println("Value:", value.String())
	fmt.Println("Gas Price:", gasPrice.String())
	fmt.Println("Gas Limit:", gasLimit)
	fmt.Println("Nonce:", nonce)
	fmt.Println("Data:", data)

	// Example of additional processing or logic
	log.Printf("Processed transaction %s", tx.Hash().Hex())

	return nil
}
