package host_call

import (
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/polkavm"
)

const (
	EmpowerCost polkavm.Gas = 10
	AssignCost
	DesignateCost
	CheckpointCost
	NewCost
	UpgradeCost
	TransferBaseCost
	QuitBaseCost
	SolicitCost
	ForgetCost
)

const (
	EmpowerID    = 5
	AssignID     = 6
	DesignateID  = 7
	CheckpointID = 8
	NewID        = 9
	UpgradeID    = 10
	TransferID   = 11
	QuitID       = 12
	SolicitID    = 13
	ForgetID     = 14
)

// Empower ΩE (ξ, ω, μ, (x, y))
func Empower(gas polkavm.Gas, regs polkavm.Registers, mem polkavm.Memory, ctx polkavm.ResultContextPair) (polkavm.Gas, polkavm.Registers, polkavm.Memory, polkavm.ResultContextPair, error) {
	if gas < EmpowerCost {
		return gas, regs, mem, ctx, polkavm.ErrOutOfGas
	}
	gas -= EmpowerCost
	// TODO implement me
	return gas, regs, mem, ctx, nil
}

// Assign ΩA(ξ, ω, μ, (x, y))
func Assign(gas polkavm.Gas, regs polkavm.Registers, mem polkavm.Memory, ctx polkavm.ResultContextPair) (polkavm.Gas, polkavm.Registers, polkavm.Memory, polkavm.ResultContextPair, error) {
	if gas < AssignCost {
		return gas, regs, mem, ctx, polkavm.ErrOutOfGas
	}
	gas -= AssignCost
	// TODO implement me
	return gas, regs, mem, ctx, nil
}

// Designate ΩD (ξ, ω, μ, (x, y))
func Designate(gas polkavm.Gas, regs polkavm.Registers, mem polkavm.Memory, ctx polkavm.ResultContextPair) (polkavm.Gas, polkavm.Registers, polkavm.Memory, polkavm.ResultContextPair, error) {
	if gas < DesignateCost {
		return gas, regs, mem, ctx, polkavm.ErrOutOfGas
	}
	gas -= DesignateCost
	// TODO implement me
	return gas, regs, mem, ctx, nil
}

// Checkpoint ΩC (ξ, ω, μ, (x, y))
func Checkpoint(gas polkavm.Gas, regs polkavm.Registers, mem polkavm.Memory, ctx polkavm.ResultContextPair) (polkavm.Gas, polkavm.Registers, polkavm.Memory, polkavm.ResultContextPair, error) {
	if gas < CheckpointCost {
		return gas, regs, mem, ctx, polkavm.ErrOutOfGas
	}
	gas -= CheckpointCost
	// TODO implement me
	return gas, regs, mem, ctx, nil
}

// New ΩN (ξ, ω, μ, (x, y))
func New(gas polkavm.Gas, regs polkavm.Registers, mem polkavm.Memory, ctx polkavm.ResultContextPair) (polkavm.Gas, polkavm.Registers, polkavm.Memory, polkavm.ResultContextPair, error) {
	if gas < NewCost {
		return gas, regs, mem, ctx, polkavm.ErrOutOfGas
	}
	gas -= NewCost
	// TODO implement me
	return gas, regs, mem, ctx, nil
}

// Upgrade ΩU (ξ, ω, μ, (x, y))
func Upgrade(gas polkavm.Gas, regs polkavm.Registers, mem polkavm.Memory, ctx polkavm.ResultContextPair) (polkavm.Gas, polkavm.Registers, polkavm.Memory, polkavm.ResultContextPair, error) {
	if gas < UpgradeCost {
		return gas, regs, mem, ctx, polkavm.ErrOutOfGas
	}
	gas -= UpgradeCost
	// TODO implement me
	return gas, regs, mem, ctx, nil
}

// Transfer ΩT (ξ, ω, μ, (x, y))
func Transfer(gas polkavm.Gas, regs polkavm.Registers, mem polkavm.Memory, ctx polkavm.ResultContextPair) (polkavm.Gas, polkavm.Registers, polkavm.Memory, polkavm.ResultContextPair, error) {
	transferCost := TransferBaseCost + polkavm.Gas(regs[polkavm.A1]) + 1<<32*polkavm.Gas(regs[polkavm.A2])
	if gas < transferCost {
		return gas, regs, mem, ctx, polkavm.ErrOutOfGas
	}
	gas -= transferCost
	// TODO implement me
	return gas, regs, mem, ctx, nil
}

// Quit ΩQ(ξ, ω, μ, (x, y))
func Quit(gas polkavm.Gas, regs polkavm.Registers, mem polkavm.Memory, ctx polkavm.ResultContextPair) (polkavm.Gas, polkavm.Registers, polkavm.Memory, polkavm.ResultContextPair, error) {
	quitCost := QuitBaseCost + polkavm.Gas(regs[polkavm.A1]) + 1<<32*polkavm.Gas(regs[polkavm.A2])
	if gas < quitCost {
		return gas, regs, mem, ctx, polkavm.ErrOutOfGas
	}
	gas -= quitCost
	// TODO implement me
	return gas, regs, mem, ctx, nil
}

// Solicit ΩS (ξ, ω, μ, (x, y), Ht)
func Solicit(gas polkavm.Gas, regs polkavm.Registers, mem polkavm.Memory, ctx polkavm.ResultContextPair, timeslot jamtime.Timeslot) (polkavm.Gas, polkavm.Registers, polkavm.Memory, polkavm.ResultContextPair, error) {
	if gas < SolicitCost {
		return gas, regs, mem, ctx, polkavm.ErrOutOfGas
	}
	gas -= SolicitCost
	// TODO implement me
	return gas, regs, mem, ctx, nil
}

// Forget ΩF (ξ, ω, μ, (x, y), Ht)
func Forget(gas polkavm.Gas, regs polkavm.Registers, mem polkavm.Memory, ctx polkavm.ResultContextPair, timeslot jamtime.Timeslot) (polkavm.Gas, polkavm.Registers, polkavm.Memory, polkavm.ResultContextPair, error) {
	if gas < ForgetCost {
		return gas, regs, mem, ctx, polkavm.ErrOutOfGas
	}
	gas -= ForgetCost
	// TODO implement me
	return gas, regs, mem, ctx, nil
}
