// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
)

// StateProcessor is a basic Processor, which takes care of transitioning
// state from one point to another.
//
// StateProcessor implements Processor.
type StateProcessor struct {
	config *params.ChainConfig // Chain configuration options
	bc     *BlockChain         // Canonical block chain
	engine consensus.Engine    // Consensus engine used for block rewards
}

// NewStateProcessor initialises a new StateProcessor.
func NewStateProcessor(config *params.ChainConfig, bc *BlockChain, engine consensus.Engine) *StateProcessor {
	return &StateProcessor{
		config: config,
		bc:     bc,
		engine: engine,
	}
}

// Process processes the state changes according to the Ethereum rules by running
// the transaction messages using the statedb and applying any rewards to both
// the processor (coinbase) and any included uncles.
//
// Process returns the receipts and logs accumulated during the process and
// returns the amount of gas that was used in the process. If any of the
// transactions failed to execute due to insufficient gas it will return an error.
func (p *StateProcessor) Process(block *types.Block, statedb *state.StateDB, cfg vm.Config) (types.Receipts, []*types.Log, uint64, error) {
	var (
		receipts    types.Receipts
		usedGas     = new(uint64)
		header      = block.Header()
		blockHash   = block.Hash()
		blockNumber = block.Number()
		allLogs     []*types.Log
		gp          = new(GasPool).AddGas(block.GasLimit())
	)

	// Mutate the block and state according to any hard-fork specs
	if p.config.DAOForkSupport && p.config.DAOForkBlock != nil && p.config.DAOForkBlock.Cmp(block.Number()) == 0 {
		misc.ApplyDAOHardFork(statedb)
	}
	var (
		context = NewEVMBlockContext(header, p.bc, nil)
		vmenv   = vm.NewEVM(context, vm.TxContext{}, statedb, p.config, cfg)
		signer  = types.MakeSigner(p.config, header.Number, header.Time)
	)
	if beaconRoot := block.BeaconRoot(); beaconRoot != nil {
		ProcessBeaconBlockRoot(*beaconRoot, vmenv, statedb)
	}
	// Iterate over and process the individual transactions
	for i, tx := range block.Transactions() {
		msg, err := TransactionToMessage(tx, signer, header.BaseFee)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("could not apply tx %d [%v]: %w", i, tx.Hash().Hex(), err)
		}
		statedb.SetTxContext(tx.Hash(), i)

		receipt, err := ApplyTransactionWithEVM(msg, p.config, gp, statedb, blockNumber, blockHash, tx, usedGas, vmenv)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("could not apply tx %d [%v]: %w", i, tx.Hash().Hex(), err)
		}
		receipts = append(receipts, receipt)
		allLogs = append(allLogs, receipt.Logs...)
	}
	// Fail if Shanghai not enabled and len(withdrawals) is non-zero.
	withdrawals := block.Withdrawals()
	if len(withdrawals) > 0 && !p.config.IsShanghai(block.Number(), block.Time()) {
		return nil, nil, 0, errors.New("withdrawals before shanghai")
	}
	// Finalize the block, applying any consensus engine specific extras (e.g. block rewards)
	p.engine.Finalize(p.bc, header, statedb, block.Body())

	return receipts, allLogs, *usedGas, nil
}

// ApplyTransactionWithEVM attempts to apply a transaction to the given state database
// and uses the input parameters for its environment similar to ApplyTransaction. However,
// this method takes an already created EVM instance as input.
func ApplyTransactionWithEVM(msg *Message, config *params.ChainConfig, gp *GasPool, statedb *state.StateDB, blockNumber *big.Int, blockHash common.Hash, tx *types.Transaction, usedGas *uint64, evm *vm.EVM) (receipt *types.Receipt, err error) {
	if evm.Config.Tracer != nil && evm.Config.Tracer.OnTxStart != nil {
		evm.Config.Tracer.OnTxStart(evm.GetVMContext(), tx, msg.From)
		if evm.Config.Tracer.OnTxEnd != nil {
			defer func() {
				evm.Config.Tracer.OnTxEnd(receipt, err)
			}()
		}
	}
	// Create a new context to be used in the EVM environment.
	txContext := NewEVMTxContext(msg)
	evm.Reset(txContext, statedb)

	// Apply the transaction to the current state (included in the env).
	result, err := ApplyMessage(evm, msg, gp)
	if err != nil {
		return nil, err
	}

	// Update the state with pending changes.
	var root []byte
	if config.IsByzantium(blockNumber) {
		statedb.Finalise(true)
	} else {
		root = statedb.IntermediateRoot(config.IsEIP158(blockNumber)).Bytes()
	}
	*usedGas += result.UsedGas

	// Create a new receipt for the transaction, storing the intermediate root and gas used
	// by the tx.
	receipt = &types.Receipt{Type: tx.Type(), PostState: root, CumulativeGasUsed: *usedGas}
	if result.Failed() {
		receipt.Status = types.ReceiptStatusFailed
	} else {
		receipt.Status = types.ReceiptStatusSuccessful
	}
	receipt.TxHash = tx.Hash()
	receipt.GasUsed = result.UsedGas

	if tx.Type() == types.BlobTxType {
		receipt.BlobGasUsed = uint64(len(tx.BlobHashes()) * params.BlobTxBlobGasPerBlob)
		receipt.BlobGasPrice = evm.Context.BlobBaseFee
	}

	// If the transaction created a contract, store the creation address in the receipt.
	if msg.To == nil {
		receipt.ContractAddress = crypto.CreateAddress(evm.TxContext.Origin, tx.Nonce())
	}

	// Set the receipt logs and create the bloom filter.
	receipt.Logs = statedb.GetLogs(tx.Hash(), blockNumber.Uint64(), blockHash)
	receipt.Bloom = types.CreateBloom(types.Receipts{receipt})
	receipt.BlockHash = blockHash
	receipt.BlockNumber = blockNumber
	receipt.TransactionIndex = uint(statedb.TxIndex())
	return receipt, err
}

// type CustomTracer struct {
// 	logger.StructLogger
// 	balanceChanges []BalanceChange
// }

// type BalanceChange struct {
// 	Address common.Address
// 	Amount  *big.Int
// }

// func (ct *CustomTracer) OnBalanceChange(address common.Address, amount *big.Int) {
// 	ct.balanceChanges = append(ct.balanceChanges, BalanceChange{Address: address, Amount: amount})
// }

// func NewCustomTracer() *CustomTracer {
// 	return &CustomTracer{
// 		StructLogger: *logger.NewStructLogger(&logger.Config{
// 			EnableMemory:     false,
// 			DisableStack:     true,
// 			DisableStorage:   false,
// 			EnableReturnData: false,
// 			Debug:            false,
// 		}),
// 		balanceChanges: []BalanceChange{},
// 	}
// }

// ApplyTransactionWithEVM attempts to apply a transaction to the given state database
// and uses the input parameters for its environment similar to ApplyTransaction. However,
// this method takes an already created EVM instance as input.
func ApplyMineTransactionWithEVM(msg *Message, config *params.ChainConfig, gp *GasPool, statedb *state.StateDB, blockNumber *big.Int, blockHash common.Hash, tx *types.Transaction, usedGas *uint64, evm *vm.EVM) (receipt *types.Receipt, internalTxs []vm.InternalTransaction, err error) {

	//tracer := NewCustomTracer()
	//evm.Config.Tracer = tracer

	if evm.Config.Tracer != nil && evm.Config.Tracer.OnTxStart != nil {
		evm.Config.Tracer.OnTxStart(evm.GetVMContext(), tx, msg.From)
		if evm.Config.Tracer.OnTxEnd != nil {
			defer func() {
				evm.Config.Tracer.OnTxEnd(receipt, err)
			}()
		}
	}

	// Create a new context to be used in the EVM environment.
	txContext := NewEVMTxContext(msg)
	evm.Reset(txContext, statedb)

	// Apply the transaction to the current state (included in the env).
	result, err := ApplyMessage(evm, msg, gp)
	if err != nil {
		return nil, nil, err
	}

	// Update the state with pending changes.
	var root []byte
	if config.IsByzantium(blockNumber) {
		statedb.Finalise(true)
	} else {
		root = statedb.IntermediateRoot(config.IsEIP158(blockNumber)).Bytes()
	}
	*usedGas += result.UsedGas

	// Create a new receipt for the transaction, storing the intermediate root and gas used
	// by the tx.
	receipt = &types.Receipt{Type: tx.Type(), PostState: root, CumulativeGasUsed: *usedGas}
	if result.Failed() {
		receipt.Status = types.ReceiptStatusFailed
	} else {
		receipt.Status = types.ReceiptStatusSuccessful
	}
	receipt.TxHash = tx.Hash()
	receipt.GasUsed = result.UsedGas

	if tx.Type() == types.BlobTxType {
		receipt.BlobGasUsed = uint64(len(tx.BlobHashes()) * params.BlobTxBlobGasPerBlob)
		receipt.BlobGasPrice = evm.Context.BlobBaseFee
	}

	// If the transaction created a contract, store the creation address in the receipt.
	if msg.To == nil {
		receipt.ContractAddress = crypto.CreateAddress(evm.TxContext.Origin, tx.Nonce())
	}

	// Set the receipt logs and create the bloom filter.
	receipt.Logs = statedb.GetLogs(tx.Hash(), blockNumber.Uint64(), blockHash)
	receipt.Bloom = types.CreateBloom(types.Receipts{receipt})
	receipt.BlockHash = blockHash
	receipt.BlockNumber = blockNumber
	receipt.TransactionIndex = uint(statedb.TxIndex())

	// Retrieve the internal transactions and balance changes from the tracer
	//internalTxs := tracer.StructLogs()
	//balanceChanges := tracer.balanceChanges

	// Log or process the internal transactions and balance changes as needed
	//fmt.Printf("Internal Transactions: %+v\n", internalTxs)
	//fmt.Printf("Balance Changes: %+v\n", balanceChanges)

	// Collect internal transactions from the EVM context
	internalTxss := evm.Context.InternalTxs

	// Log or return the internal transactions as needed
	for _, internalTx := range internalTxss {
		// Example: Print to console (or handle as needed)
		internalTxs = append(internalTxs, internalTx)
		fmt.Printf("Internal Tx: From %s To %s Value %s Data %x\n",
			internalTx.From.Hex(), internalTx.To.Hex(), internalTx.Value.String(), internalTx.Data)
	}

	// Reset internal transactions for the next run
	evm.Context.InternalTxs = nil

	return receipt, internalTxs, err
}

// ApplyTransaction attempts to apply a transaction to the given state database
// and uses the input parameters for its environment. It returns the receipt
// for the transaction, gas used and an error if the transaction failed,
// indicating the block was invalid.
func ApplyTransaction(config *params.ChainConfig, bc ChainContext, author *common.Address, gp *GasPool, statedb *state.StateDB, header *types.Header, tx *types.Transaction, usedGas *uint64, cfg vm.Config) (*types.Receipt, error) {
	msg, err := TransactionToMessage(tx, types.MakeSigner(config, header.Number, header.Time), header.BaseFee)
	if err != nil {
		return nil, err
	}
	// Create a new context to be used in the EVM environment
	blockContext := NewEVMBlockContext(header, bc, author)
	txContext := NewEVMTxContext(msg)
	vmenv := vm.NewEVM(blockContext, txContext, statedb, config, cfg)
	return ApplyTransactionWithEVM(msg, config, gp, statedb, header.Number, header.Hash(), tx, usedGas, vmenv)
}

// ApplyTransaction attempts to apply a transaction to the given state database
// and uses the input parameters for its environment. It returns the receipt
// for the transaction, gas used and an error if the transaction failed,
// indicating the block was invalid.
func ApplyMineTransaction(config *params.ChainConfig, bc ChainContext, author *common.Address, gp *GasPool, statedb *state.StateDB, header *types.Header, tx *types.Transaction, usedGas *uint64, cfg vm.Config) (*types.Receipt, []vm.InternalTransaction, error) {
	msg, err := TransactionToMessage(tx, types.MakeSigner(config, header.Number, header.Time), header.BaseFee)
	if err != nil {
		return nil, nil, err
	}
	// Create a new context to be used in the EVM environment
	blockContext := NewEVMBlockContext(header, bc, author)
	txContext := NewEVMTxContext(msg)
	vmenv := vm.NewEVM(blockContext, txContext, statedb, config, cfg)
	return ApplyMineTransactionWithEVM(msg, config, gp, statedb, header.Number, header.Hash(), tx, usedGas, vmenv)
}

// ProcessBeaconBlockRoot applies the EIP-4788 system call to the beacon block root
// contract. This method is exported to be used in tests.
func ProcessBeaconBlockRoot(beaconRoot common.Hash, vmenv *vm.EVM, statedb *state.StateDB) {
	if vmenv.Config.Tracer != nil && vmenv.Config.Tracer.OnSystemCallStart != nil {
		vmenv.Config.Tracer.OnSystemCallStart()
	}
	if vmenv.Config.Tracer != nil && vmenv.Config.Tracer.OnSystemCallEnd != nil {
		defer vmenv.Config.Tracer.OnSystemCallEnd()
	}

	// If EIP-4788 is enabled, we need to invoke the beaconroot storage contract with
	// the new root
	msg := &Message{
		From:      params.SystemAddress,
		GasLimit:  30_000_000,
		GasPrice:  common.Big0,
		GasFeeCap: common.Big0,
		GasTipCap: common.Big0,
		To:        &params.BeaconRootsAddress,
		Data:      beaconRoot[:],
	}
	vmenv.Reset(NewEVMTxContext(msg), statedb)
	statedb.AddAddressToAccessList(params.BeaconRootsAddress)
	_, _, _ = vmenv.Call(vm.AccountRef(msg.From), *msg.To, msg.Data, 30_000_000, common.U2560)
	statedb.Finalise(true)
}

// // AccountState captures the state of an account, including its storage.
// type AccountState struct {
// 	Balance string
// 	Nonce   uint64
// 	Code    []byte
// 	Storage map[common.Hash]common.Hash
// }

// // CaptureState captures the state of all accounts in the state database.
// func CaptureState(statedb *state.StateDB, config *state.DumpConfig) (map[common.Address]AccountState, error) {
// 	accounts := make(map[common.Address]AccountState)

// 	// RawDump returns the entire state as a map of address to account.
// 	dump := statedb.RawDump(config)

// 	for addr, acc := range dump.Accounts {
// 		storage := make(map[common.Hash]common.Hash)
// 		for key, value := range acc.Storage {
// 			storage[key] = common.HexToHash(value)
// 		}
// 		accounts[common.HexToAddress(addr)] = AccountState{
// 			Balance: acc.Balance,
// 			Nonce:   acc.Nonce,
// 			Code:    acc.Code,
// 			Storage: storage,
// 		}
// 	}
// 	return accounts, nil
// }

// // SimulateTransaction simulates a transaction and traces internal calls up to a specified depth.
// func SimulateTransaction(db ethdb.Database, snap *snapshot.Tree, tx *types.Transaction, block *types.Block, cfg *params.ChainConfig, depth int) (*types.Receipt, interface{}, map[common.Address]AccountState, map[common.Address]AccountState, error) {
// 	// Ensure block root hash is valid
// 	root := block.Root()
// 	if root == (common.Hash{}) {
// 		return nil, nil, nil, nil, fmt.Errorf("invalid block root hash")
// 	}

// 	// Initialize the state database with 3 parameters
// 	statedb, err := state.New(root, state.NewDatabase(db), snap)
// 	if err != nil {
// 		return nil, nil, nil, nil, fmt.Errorf("failed to initialize state database: %v", err)
// 	}

// 	// Capture the state before the transaction
// 	dumpConfig := state.DumpConfig{
// 		SkipCode:          false,
// 		SkipStorage:       false,
// 		OnlyWithAddresses: false,
// 		Start:             nil,
// 		Max:               0,
// 	}
// 	stateBefore, err := CaptureState(statedb, &dumpConfig)
// 	if err != nil {
// 		return nil, nil, nil, nil, fmt.Errorf("failed to capture state before transaction: %v", err)
// 	}

// 	// Create the EVM context
// 	msg := types.NewMessage(tx.From(), tx.To(), tx.Nonce(), tx.Value(), tx.Gas(), tx.GasPrice(), tx.Data(), false)
// 	header := block.Header()
// 	vmctx := NewEVMContext(msg, header, statedb, &cfg.ChainID)

// 	// Create the EVM environment
// 	evm := NewEVM(vmctx, statedb, cfg, NewEVMConfig())

// 	// Create a tracer to capture internal transactions
// 	tracer := tracers.NewJSONTracer(&tracers.TracerConfig{
// 		Debug:            true,
// 		EnableMemory:     true,
// 		EnableReturnData: true,
// 		EnableStorage:    true,
// 		Limit:            int(depth),
// 	})

// 	// Process the transaction with tracing
// 	_, receipt, err := ApplyTransaction(cfg, nil, &header, tx, statedb, evm, tracer)
// 	if err != nil {
// 		return nil, nil, nil, nil, fmt.Errorf("failed to apply transaction: %v", err)
// 	}

// 	// Capture the state after the transaction
// 	stateAfter, err := CaptureState(statedb, &dumpConfig)
// 	if err != nil {
// 		return nil, nil, nil, nil, fmt.Errorf("failed to capture state after transaction: %v", err)
// 	}

// 	// Get the traced logs
// 	logs := tracer.GetResult()

// 	return receipt, logs, stateBefore, stateAfter, nil
// }
