# Gray paper implementation in go

An attempt to document and map gray paper formulas to go code
with references to both the implementation and the formula
while explaining our interpretation.

We use a Go-like pseudocode to explain the formula and define a function signature. 

Contents:
- [PVM (Appendix A And B)](#pvm-appendix-a-and-b)
- [Index Of Notation](#index-of-notation)



## PVM (Appendix A And B)

### Formula [241](https://graypaper.fluffylabs.dev/#/c71229b/23b60123b601)

`func X func(x uint32) uint32 { ... }`

Where:
- `x` - The input of `n` octets. For simplicity, we use `uint32` as the max possible value of little-endian encoded bytes. For example a little-endian encoded number composed of 1 or 2 or 3 bytes can be contained within `uint32` that is represented by 4 bytes. 

### Formula [258](https://graypaper.fluffylabs.dev/#/c71229b/283002283002) 
<pre>
func Y(p []byte) (<b>c</b> []byte, ω [13]uint32, μ []byte) { 
    // ...
}
</pre>

Where:
 - `p` - The standard program code format, which includes: instructions, jump table, RAM and registers at program start.
 - `ω` - Registers
 - `μ` - RAM
 - <code>**c**</code> - Program code
 - <code>**o**</code> - ? 
 - <code>**w**</code> - ?
 - <code>*z*</code> - ? 
 - <code>*s*</code> - ? 
### Formula [171]()
```
T ≡ (s ∈ N_S, d ∈ N_S, a ∈ N_B, m ∈ Y_WT, g ∈ N_G)
type DeferredTransfer struct {
    SenderServiceIndex uint32 // service index
    ReceiverServiceIndex uint32 // service index
    Balance uint64 // balance value
    Memo [128]byte // memo
    GasLimit // gas limit g 
}
```

### Formula [256](https://graypaper.fluffylabs.dev/#/c71229b/28e30128e301)

### Formulas [265-266](https://graypaper.fluffylabs.dev/#/c71229b/29fd0129fd01)

<pre>

// Formula <a href="https://graypaper.fluffylabs.dev/#/c71229b/29fd0129fd01">265</a>
func Ψ<sub>M</sub>(p []byte, ı uint32, ϱ uint64, a [<a href="#constants">Z<sub>I</sub></a>]byte, f func(...uint32) uint32, x X) (g uint64, []byte | ∞ | ☇, X) { 
    c, ω, μ := Y(p)
    if c == nil {
        return ϱ, ☇, x
    }

    // Formula <a href="https://graypaper.fluffylabs.dev/#/c71229b/296702296702">266</a>
    R := func(ε ∎ | ∞, ı uint32, ϱ uint64, a [<a href="#constants">Z<sub>I</sub></a>]byte, f func(...uint32) uint32, x X) (g uint64, []byte | ∞ | ☇, X) {
        switch ε {
        case ∎: 
            // not sure this is the correct interpretation
            if ω′[10] < ω′[11] && len(μ′) < ω′[11] {   
                return ϱ′, μ′[ω′[10]:ω′[11]], x
            } else {
                return ϱ′, []byte{}, x
            }
        case ∞:
            return ϱ′, ∞, x
        default:
            return ϱ′, ☇, x
        }
    }

    ε, ı′, ϱ′, ω′, μ′, x := Ψ<sub>H</sub>(c, ı, ϱ, ω, μ, f, x)

    return R(ε, ı′, ϱ′, ω′, μ′, x)
}

</pre>

Where:
- `p` - The standard program code
- `ı` - Instruction counter
- `ϱ` - Gas counter
- `ε` - Exit code
- `a` - argument data (a series of octets with at most Z<sub>I</sub> elements)
- `f` - Host call function
- `x` - ??? (Signed extension function operating on an input of n octets as Xn)

## Formula [272](https://graypaper.fluffylabs.dev/#/c71229b/2b31002b3100)

<pre>
type X struct {
    d map[uint32]state.ServiceAccount
    s uint32 // service account index
    u U // partial state
    i uint32 
    t []T 
}
</pre>


## Index Of Notation

### Types
- Y: `[]byte` set of octets
- N: `uint32` - non-negative integers
- N<sub>G</sub>: `uint64` - Gas
- V<sub>μ</sub>: The set of validly readable indices for PVM RAM μ.
- ⟦N<sub>R</sub>⟧<sub>13</sub>: `[13]uint32` - Registers 

### Constants:
- <code>const Z<sub>I</sub> = 2<sup>24</sup> = 1<<32</code> - The standard pvm program initialization input data size. See equation A.7.

### Exit reasons:
- `▸` - ?
- `∎` - halt
- `☇` - panic
- `∞` - out of gas
