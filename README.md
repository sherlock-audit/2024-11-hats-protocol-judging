# Issue H-1: Detaching HSG when there's non-unregistered owners who no longer own the hat would give them control over the multi-sig 

Source: https://github.com/sherlock-audit/2024-11-hats-protocol-judging/issues/4 

## Found by 
bughuntoor
### Summary
After a user no longer owns a hat, although they are no longer treated as a valid signer, they remain an `owner` within the Safe, until `removeSigner` is called 

```solidity
  function detachHSG() public {
    _checkUnlocked();
    _checkOwner();
    ISafe s = safe; // save SLOAD

    // first remove as guard, then as module
    s.execRemoveHSGAsGuard();
    s.execDisableHSGAsOnlyModule();
    emit Detached();
  }
```

When HSG is detached, it does not check if there's any Safe owners who no longer wear the necessary hat. For this reason, if there's such owners, they'll remain rights within the multi-sig. Depending on their number, they might be able to overturn the multisig, or at least disallow them to reach quorum.

However, this attack can further be weaponized if one of the signer hats has admin rights over another signer hat. If the said admin hat wants to overturn the multisig and gain full access of it upon detaching, they can simply front-run the `detachHSG` call and do a loop of 1) transferring the lower hat to a new address 2) claiming it as a signer. Then, when  the `detachHSG` executes, all of these addresses that the attacker had looped through would be owners of the safe and in most cases that should be enough to fully overturn the multi-sig and claim full custody of it.


### Root Cause
`detachHSG` does not check if there are Safe owners who no longer wear the necessary hat.

### Attack Path
1. DAO plans to detach from HSG
2. There exists a user who has admin hat over a signer hat which has a set max supply of 1.
3. DAO calls detach from HSG
4. The admin hat owner front-runs the tx and does a loop of transferring the hat and adding it as a signer. This gives a lot of wallets `owner` rights within the Safe, which would otherwise be worthless if HSG remains active
5.  The DAO gets detached and all of the wallets the admin hat owner had looped through now are owners within the Safe
6.  This would usually give full custody to the attacker, or at the very least guarantee the DAO is not able to execute anything on their own.

### Impact
Attacker can gain full custody over a Safe upon HSG detachment 

### Affected Code
https://github.com/sherlock-audit/2024-11-hats-protocol/blob/main/hats-zodiac/src/HatsSignerGate.sol#L341

### Mitigation
Upon detaching HSG, loop through all Safe owners and in case a wallet does not wear the necessary hat, unregister them as a signer.

# Issue M-1: Signer can avoid restrictions and change `safe` state variables 

Source: https://github.com/sherlock-audit/2024-11-hats-protocol-judging/issues/3 

## Found by 
bughuntoor
### Summary
In order to make sure that a delegatecall does not change Safe's state, HSG's `checkTransaction` stores the current threshold, owners list and fallback handler. Then, after the call is executed, `checkAfterExecution` is supposed to verify that these variables have not been changed.

```solidity
    if (operation == Enum.Operation.DelegateCall) {
      // case: DELEGATECALL
      // We disallow delegatecalls to unapproved targets
      if (!enabledDelegatecallTargets[to]) revert DelegatecallTargetNotEnabled();

      // Otherwise record the existing owners and threshold for post-flight checks to ensure that Safe state has not
      // been altered
      _existingOwnersHash = keccak256(abi.encode(owners));
      _existingThreshold = threshold;
      _existingFallbackHandler = safe.getSafeFallbackHandler();
```

However, since the `checkTransaction` can be re-entered by a new call, these restrictions can easily be bypassed. If the delegatecall changes the owners and the threshold, the executing signer can then just provide a new transaction to be executed with the new owners being just him and threshold set to 1. This will then override the above stored variables. Because of this the `checkAfterExecution`  check will also succeed.


### Root Cause

Possible reentrancy within `checkTransaction`

### Attack Path
1. Signers sign a tx which would alter the owners list and set the threshold to 1.
2. Within that `delegatecall`, the only remaining owner signs a new transaction and executes it. It doesn't realistically mater what the tx is.
3. `checkTransaction` is entered. `_existingOwnersHash ` and `_existingThreshold ` are overwritten to their new values.
4. The `checkAfterExecution` on both the inner and the outer call check against the altered values, hence they both succeed.
5. In the end, the intended restrictions are bypassed and the ownerlist and threshold are both overwritten.
6. The user who has remained the only owner has full access over the multi-sig until the other owners re-claim their hats.

### Affected Code 
https://github.com/sherlock-audit/2024-11-hats-protocol/blob/main/hats-zodiac/src/HatsSignerGate.sol#L471

### Impact
Users can bypassed intended restrictions not to be able to overwrite the owner list and threshold variables.

### Mitigation

If `checkTransaction` is entered, and the transient variables have already been assigned values, revert if the values differ from the current ones.

# Issue M-2: Users can bypass intended restrictions and add modules to the Safe 

Source: https://github.com/sherlock-audit/2024-11-hats-protocol-judging/issues/5 

## Found by 
bughuntoor
### Summary
If the call intended to be executed is a `delegatecall`, the contract's `checkTransaction` stores the current list of owners. Then in the `checkAfterExecution` it verifies that the list  has not changed. The `checkAfterExecution` function also checks that no modules have been added.

```solidity
    if (operation == Enum.Operation.DelegateCall) {
      // case: DELEGATECALL
      // We disallow delegatecalls to unapproved targets
      if (!enabledDelegatecallTargets[to]) revert DelegatecallTargetNotEnabled();

      // Otherwise record the existing owners and threshold for post-flight checks to ensure that Safe state has not
      // been altered
      _existingOwnersHash = keccak256(abi.encode(owners));
      _existingThreshold = threshold;
      _existingFallbackHandler = safe.getSafeFallbackHandler();
```

However, both of these assume that the owner or module to be added is added to the regular functions, which uses an array as a sorted list. The `delegatecall` however allows to simply bypass the intended functions and change the mapping values in such way that an address is given owner rights without actually being in that ordered list. 

This renders the following checks useless.

### Affected Code
https://github.com/sherlock-audit/2024-11-hats-protocol/blob/main/hats-zodiac/src/HatsSignerGate.sol#L966

### Attack Path

1. Signers do a `delegatecall` 
2. Said delegatecall adds a module by simply setting the storage value `modules[moduleAddr] = randomAddr`
3. This will bypass the `checkAfterExecution` checks and renders them useless.

Also breaks the following invariant which should never be broken
> There should never be more than 1 module enabled on the safe

### Impact
Users can bypass intended restrictions 

### Mitigation
Fix is non-trivial.

# Issue M-3: Signers can use old signatures/ repeat signatures in case the HSG guard adds new signers 

Source: https://github.com/sherlock-audit/2024-11-hats-protocol-judging/issues/6 

## Found by 
bughuntoor
### Summary
The order for a regular transaction is that it is first sent to the Safe, if the provided signatures reach the set threshold within the Safe, `checkTransaction` is called within the HSG. It must be noted that Safe only checks the first `threshold` signatures provided.

Then, within the `checkTransaction` function within HSG, before the owner list and the threshold are fetched,  a call to the guard is made

```solidity
    if (guard != address(0)) {
      BaseGuard(guard).checkTransaction(
        to,
        value,
        data,
        operation,
        // Zero out the redundant transaction information only used for Safe multisig transctions.
        0,
        0,
        0,
        address(0),
        payable(0),
        "",
        address(0)
      );
    }

    // get the existing owners and threshold
    address[] memory owners = safe.getOwners();
    uint256 threshold = safe.getThreshold();
```

Now, if that call does any logic which increases the current `threshold`, this would allow for usage of old signatures, or repeated signatures. One possible reason why the guard could do that would be 1) make sure there's no unregistered hat owners and register them 2) change the threshold config based on any outside logic. In either case, the appended signatures after the initial Safe threshold, could actually be repeated.

### Root Cause
Guard could increase the threshold and the last to be checked signatures are not actually verified. 

### Affected Code
https://github.com/sherlock-audit/2024-11-hats-protocol/blob/main/hats-zodiac/src/HatsSignerGate.sol#L441

### Attack Path
Consider the following scenario: 
1. The multi-sig always requires x/x signatures to execute tx
2. To properly enforce said rule, the HSG guard checks if there's a non-registered hat owner and registers them as a signer
3. Currently there are 3/3 registered signers willing to sign a tx. There's a 4th non-registered owner who has a signer hat.
4. The signers submit the tx to Safe with signatures `[Alice, Bob, John, Alice]`. 
5. Since the Safe's threshold is still 3, it only checks that the first three signatures are valid 
6. `checkTransaction` is entered. The guard registers the 4th hat owner as a signer and increases the threshold to 4.
7. HSG now checks 4 signatures. Since all of the signers are valid hat owners, the transaction succeeds.
8. The multi-sig managed to execute a tx with only 3 valid signatures, although 4 were originally needed.

### Impact
DAOs can execute transaction with less than threshold valid signatures.

### Mitigation
Make sure the Guard does not increase neither of the number of owners and the threshold.

# Issue M-4: _entrancyCounter Reentry check can be bypassed by modifying Safe.nonce value 

Source: https://github.com/sherlock-audit/2024-11-hats-protocol-judging/issues/23 

## Found by 
Boy2000
### Summary

HSG has safeguards to prevent signers and modules changing the Safe state. For the `checkTransaction` flow it uses two layer approach:

1. Whitelist of `enabledDelegatecallTargets[]`.

2. On execution, HSG takes a snapshot of the safe state, and afterwards at `checkAfterExecution -> _checkSafeState` it verifies the state has not been tampered with.

The 2nd layer can be bypassed.

### Root Cause

HSG team correctly identified that a delegate call can invoke `checkTransaction` outside of the regular Safe flow, and in order to mitigate it they track `Safe.nonce` value:

https://github.com/sherlock-audit/2024-11-hats-protocol/blob/main/hats-zodiac/src/HatsSignerGate.sol#L430

`we rely on the invariant that the Safe nonce increments every time Safe.execTransaction calls out to IGuard.checkTransaction`.

As such the following is mitigated:

```solidity
execTransaction -> checkTransaction
add owner
direct call checkTransaction - to update the snapshot
```

The direct call fails since `Safe.nonce` has not been incremented.

However the issue is that a delegated call can modify any Safe value, including the `nonce`, thus the attack becomes:

```solidity
execTransaction -> checkTransaction
add owner
modify nonce slot
direct call checkTransaction - to update the snapshot
```

### Internal pre-conditions

_No response_

### External pre-conditions

_No response_

### Attack Path

_No response_

### Impact

delegatecalls can modify critical Safe parameters.

### PoC

It's a complicated POC and the contest ends soon, I will add one in the comments during judging phase if required.

### Mitigation

_No response_

